from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aigov.config import Settings, get_settings
from aigov.domains.audit.service import AuditLog
from aigov.domains.authorization.service import (
    AuthorizationCheck,
    build_snapshot_parts,
    evaluate_authorization,
    governance_fingerprint,
    sign_authorization,
)
from aigov.domains.evidence.service import (
    COLLECTOR_VERSION,
    ControlAssessment,
    assess_controls,
    controls_to_policy_document,
    reject_upload,
)
from aigov.domains.findings.service import (
    FindingRuleError,
    auto_promotes,
    incident_fingerprint_records,
    incident_title,
    open_incidents_to_policy_document,
    validate_finding,
)
from aigov.domains.identity.principal import Principal
from aigov.domains.policy.engine import PolicyEngine, PolicyEvaluation
from aigov.domains.risk.engine import assess as assess_risk
from aigov.domains.workflow.service import (
    ExceptionRuleError,
    as_utc,
    compute_due_at,
    default_expires_at,
    exception_fingerprint_records,
    exceptions_to_policy_document,
    validate_exception_request,
)
from aigov.infrastructure.ids import new_id, utcnow
from aigov.infrastructure.models import (
    AISystemModel,
    ApprovalModel,
    DeploymentAuthorizationModel,
    EvidenceArtifactModel,
    ExceptionModel,
    FindingModel,
    GovernanceDecisionModel,
    IncidentModel,
    PolicyDecisionModel,
    RiskAssessmentModel,
    WorkflowCaseModel,
)
from aigov.infrastructure.object_store import ObjectStorePort


class NotFoundError(Exception):
    pass


class EvidenceRejectedError(Exception):
    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class SegregationOfDutiesError(Exception):
    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class ExceptionRejectedError(Exception):
    def __init__(self, detail: str, code: str = "EXCEPTION_REJECTED") -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code


class FindingRejectedError(Exception):
    def __init__(self, detail: str, code: str = "FINDING_REJECTED") -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code


APPROVER_ROLES = {
    "privacy": ("privacy",),
    "security": ("security",),
    "risk": ("risk_reviewer",),
    "owner": ("owner",),
}
EXCEPTION_GRANT_ROLES = ("privacy", "security", "risk_reviewer")
FINDING_REVIEW_ROLES = EXCEPTION_GRANT_ROLES


@dataclass
class GateResult:
    decision: PolicyDecisionModel
    snapshot: GovernanceDecisionModel
    authorization: DeploymentAuthorizationModel | None


def _slug(name: str) -> str:
    cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in name).strip("-")
    return cleaned[:48] or "system"


def _digest(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _sha256(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


class GovernanceService:
    def __init__(
        self,
        session: AsyncSession,
        policy_engine: PolicyEngine,
        object_store: ObjectStorePort,
        settings: Settings | None = None,
    ) -> None:
        self.session = session
        self.policy_engine = policy_engine
        self.object_store = object_store
        self.settings = settings or get_settings()
        self.audit = AuditLog(session)

    async def register(self, principal: Principal, registration: dict[str, Any]) -> AISystemModel:
        system_id = new_id("sys")
        version_id = new_id("ver")
        now = utcnow()
        row = AISystemModel(
            id=system_id,
            tenant_id=principal.tenant_id,
            urn=f"urn:ai-gov:{principal.tenant_id}:aisystem:{_slug(registration['name'])}-{system_id[-6:]}",
            name=registration["name"],
            system_type=registration["systemType"],
            business_purpose=registration["businessPurpose"],
            owner=registration["owner"],
            environment=registration["environment"],
            data_classification=registration["dataClassification"],
            geography=registration["geography"],
            autonomy_level=registration["autonomyLevel"],
            status="DRAFT",
            registration=registration,
            human_oversight=list(registration.get("humanOversight") or []),
            current_version_id=version_id,
            created_at=now,
            updated_at=now,
        )
        self.session.add(row)
        await self.audit.append(
            tenant_id=principal.tenant_id,
            aggregate_id=system_id,
            event_type="AISystemRegistered",
            actor=_actor(principal),
            payload={"name": row.name, "urn": row.urn, "versionId": version_id},
        )
        await self.session.commit()
        await self.session.refresh(row)
        return row

    async def list_systems(self, principal: Principal) -> list[AISystemModel]:
        result = await self.session.scalars(
            select(AISystemModel)
            .where(AISystemModel.tenant_id == principal.tenant_id)
            .order_by(AISystemModel.created_at.desc())
        )
        return list(result)

    async def get_system(self, principal: Principal, system_id: str) -> AISystemModel:
        row = await self.session.scalar(
            select(AISystemModel).where(
                AISystemModel.id == system_id,
                AISystemModel.tenant_id == principal.tenant_id,
            )
        )
        if row is None:
            raise NotFoundError(system_id)
        return row

    async def latest_assessment(
        self, principal: Principal, system_id: str
    ) -> RiskAssessmentModel | None:
        return await self.session.scalar(
            select(RiskAssessmentModel)
            .where(
                RiskAssessmentModel.tenant_id == principal.tenant_id,
                RiskAssessmentModel.system_id == system_id,
            )
            .order_by(RiskAssessmentModel.assessed_at.desc())
            .limit(1)
        )

    async def latest_decision(
        self, principal: Principal, system_id: str
    ) -> PolicyDecisionModel | None:
        return await self.session.scalar(
            select(PolicyDecisionModel)
            .where(
                PolicyDecisionModel.tenant_id == principal.tenant_id,
                PolicyDecisionModel.system_id == system_id,
            )
            .order_by(PolicyDecisionModel.decided_at.desc())
            .limit(1)
        )

    async def latest_snapshot(
        self, principal: Principal, system_id: str
    ) -> GovernanceDecisionModel | None:
        return await self.session.scalar(
            select(GovernanceDecisionModel)
            .where(
                GovernanceDecisionModel.tenant_id == principal.tenant_id,
                GovernanceDecisionModel.system_id == system_id,
            )
            .order_by(GovernanceDecisionModel.created_at.desc())
            .limit(1)
        )

    async def latest_authorization(
        self, principal: Principal, system_id: str
    ) -> DeploymentAuthorizationModel | None:
        return await self.session.scalar(
            select(DeploymentAuthorizationModel)
            .where(
                DeploymentAuthorizationModel.tenant_id == principal.tenant_id,
                DeploymentAuthorizationModel.system_id == system_id,
            )
            .order_by(DeploymentAuthorizationModel.issued_at.desc())
            .limit(1)
        )

    async def get_authorization(
        self, principal: Principal, system_id: str, authorization_id: str
    ) -> DeploymentAuthorizationModel:
        await self.get_system(principal, system_id)
        row = await self.session.scalar(
            select(DeploymentAuthorizationModel).where(
                DeploymentAuthorizationModel.id == authorization_id,
                DeploymentAuthorizationModel.tenant_id == principal.tenant_id,
                DeploymentAuthorizationModel.system_id == system_id,
            )
        )
        if row is None:
            raise NotFoundError(authorization_id)
        return row

    async def list_approvals(self, principal: Principal, system_id: str) -> list[ApprovalModel]:
        result = await self.session.scalars(
            select(ApprovalModel)
            .where(
                ApprovalModel.tenant_id == principal.tenant_id,
                ApprovalModel.system_id == system_id,
            )
            .order_by(ApprovalModel.recorded_at.asc())
        )
        return list(result)

    async def list_evidence(
        self, principal: Principal, system_id: str
    ) -> list[EvidenceArtifactModel]:
        result = await self.session.scalars(
            select(EvidenceArtifactModel)
            .where(
                EvidenceArtifactModel.tenant_id == principal.tenant_id,
                EvidenceArtifactModel.system_id == system_id,
            )
            .order_by(EvidenceArtifactModel.collected_at.desc())
        )
        return list(result)

    async def control_posture(
        self, principal: Principal, system_id: str
    ) -> list[ControlAssessment]:
        system = await self.get_system(principal, system_id)
        assessment = await self.latest_assessment(principal, system_id)
        artifacts = await self.list_evidence(principal, system_id)
        return assess_controls(system, assessment, artifacts)

    async def list_cases(self, principal: Principal, system_id: str) -> list[WorkflowCaseModel]:
        result = await self.session.scalars(
            select(WorkflowCaseModel)
            .where(
                WorkflowCaseModel.tenant_id == principal.tenant_id,
                WorkflowCaseModel.system_id == system_id,
            )
            .order_by(WorkflowCaseModel.opened_at.desc())
        )
        return list(result)

    async def latest_case(self, principal: Principal, system_id: str) -> WorkflowCaseModel | None:
        return await self.session.scalar(
            select(WorkflowCaseModel)
            .where(
                WorkflowCaseModel.tenant_id == principal.tenant_id,
                WorkflowCaseModel.system_id == system_id,
            )
            .order_by(WorkflowCaseModel.opened_at.desc())
            .limit(1)
        )

    async def open_case(self, principal: Principal, system_id: str) -> WorkflowCaseModel | None:
        return await self.session.scalar(
            select(WorkflowCaseModel)
            .where(
                WorkflowCaseModel.tenant_id == principal.tenant_id,
                WorkflowCaseModel.system_id == system_id,
                WorkflowCaseModel.status == "OPEN",
            )
            .order_by(WorkflowCaseModel.opened_at.desc())
            .limit(1)
        )

    async def list_exceptions(self, principal: Principal, system_id: str) -> list[ExceptionModel]:
        result = await self.session.scalars(
            select(ExceptionModel)
            .where(
                ExceptionModel.tenant_id == principal.tenant_id,
                ExceptionModel.system_id == system_id,
            )
            .order_by(ExceptionModel.requested_at.desc())
        )
        return list(result)

    async def get_exception(
        self, principal: Principal, system_id: str, exception_id: str
    ) -> ExceptionModel:
        await self.get_system(principal, system_id)
        row = await self.session.scalar(
            select(ExceptionModel).where(
                ExceptionModel.id == exception_id,
                ExceptionModel.tenant_id == principal.tenant_id,
                ExceptionModel.system_id == system_id,
            )
        )
        if row is None:
            raise NotFoundError(exception_id)
        return row

    async def list_findings(self, principal: Principal, system_id: str) -> list[FindingModel]:
        result = await self.session.scalars(
            select(FindingModel)
            .where(
                FindingModel.tenant_id == principal.tenant_id,
                FindingModel.system_id == system_id,
            )
            .order_by(FindingModel.recorded_at.desc())
        )
        return list(result)

    async def get_finding(
        self, principal: Principal, system_id: str, finding_id: str
    ) -> FindingModel:
        await self.get_system(principal, system_id)
        row = await self.session.scalar(
            select(FindingModel).where(
                FindingModel.id == finding_id,
                FindingModel.tenant_id == principal.tenant_id,
                FindingModel.system_id == system_id,
            )
        )
        if row is None:
            raise NotFoundError(finding_id)
        return row

    async def list_incidents(self, principal: Principal, system_id: str) -> list[IncidentModel]:
        result = await self.session.scalars(
            select(IncidentModel)
            .where(
                IncidentModel.tenant_id == principal.tenant_id,
                IncidentModel.system_id == system_id,
            )
            .order_by(IncidentModel.opened_at.desc())
        )
        return list(result)

    async def get_incident(
        self, principal: Principal, system_id: str, incident_id: str
    ) -> IncidentModel:
        await self.get_system(principal, system_id)
        row = await self.session.scalar(
            select(IncidentModel).where(
                IncidentModel.id == incident_id,
                IncidentModel.tenant_id == principal.tenant_id,
                IncidentModel.system_id == system_id,
            )
        )
        if row is None:
            raise NotFoundError(incident_id)
        return row

    async def assess(self, principal: Principal, system_id: str) -> RiskAssessmentModel:
        system = await self.get_system(principal, system_id)
        result = assess_risk(system.registration)
        now = utcnow()
        row = RiskAssessmentModel(
            id=new_id("ra"),
            tenant_id=principal.tenant_id,
            system_id=system.id,
            score=result.score,
            risk_band=result.risk_band,
            confidence=result.confidence,
            drivers=[driver.__dict__ for driver in result.drivers],
            hard_constraints=result.hard_constraints,
            missing_inputs=result.missing_inputs,
            engine_version=result.engine_version,
            assessed_at=now,
        )
        system.status = _status_after_assessment(result.risk_band, result.confidence)
        system.updated_at = now
        self.session.add(row)
        await self.audit.append(
            tenant_id=principal.tenant_id,
            aggregate_id=system.id,
            event_type="RiskAssessmentCompleted",
            actor=_actor(principal),
            payload={
                "score": result.score,
                "riskBand": result.risk_band,
                "confidence": result.confidence,
                "assessmentId": row.id,
            },
        )
        await self.session.commit()
        await self.session.refresh(row)
        return row

    async def record_approval(
        self, principal: Principal, system_id: str, function: str, approved: bool
    ) -> None:
        system = await self.get_system(principal, system_id)
        allowed_roles = APPROVER_ROLES[function]
        if not principal.has_role(*allowed_roles):
            raise SegregationOfDutiesError(
                f"principal lacks required role for {function} approval"
            )
        if function != "owner" and principal.actor_id == _owner_actor(system):
            raise SegregationOfDutiesError("requester cannot be sole approver")
        now = utcnow()
        row = ApprovalModel(
            id=new_id("appr"),
            tenant_id=principal.tenant_id,
            system_id=system.id,
            function=function,
            approved=approved,
            actor_id=principal.actor_id,
            recorded_at=now,
        )
        self.session.add(row)
        await self.audit.append(
            tenant_id=principal.tenant_id,
            aggregate_id=system.id,
            event_type="ApprovalGranted" if approved else "ApprovalRevoked",
            actor=_actor(principal),
            payload={"function": function, "approved": approved},
        )
        await self.session.commit()

    async def attach_oversight(
        self, principal: Principal, system_id: str, controls: list[str]
    ) -> AISystemModel:
        system = await self.get_system(principal, system_id)
        merged = list(dict.fromkeys([*system.human_oversight, *controls]))
        system.human_oversight = merged
        registration = dict(system.registration)
        registration["humanOversight"] = merged
        system.registration = registration
        system.updated_at = utcnow()
        await self.audit.append(
            tenant_id=principal.tenant_id,
            aggregate_id=system.id,
            event_type="HumanOversightAttached",
            actor=_actor(principal),
            payload={"controls": merged},
        )
        await self.session.commit()
        await self.session.refresh(system)
        return system

    async def attach_evidence(
        self,
        principal: Principal,
        system_id: str,
        *,
        evidence_type: str,
        filename: str,
        content: bytes,
        collected_at: datetime | None = None,
        bound_version_id: str | None = None,
        media_type: str = "text/plain",
    ) -> EvidenceArtifactModel:
        system = await self.get_system(principal, system_id)
        rejected = reject_upload(content, evidence_type, self.settings.evidence_max_bytes)
        if rejected:
            raise EvidenceRejectedError(rejected)
        evidence_id = new_id("evd")
        key = f"{principal.tenant_id}/{system.id}/{evidence_id}"
        uri = await self.object_store.put(key, content)
        digest = _sha256(content)
        stored = await self.object_store.get(key)
        verification = "VERIFIED" if _sha256(stored) == digest else "FAIL"
        now = utcnow()
        row = EvidenceArtifactModel(
            id=evidence_id,
            tenant_id=principal.tenant_id,
            system_id=system.id,
            bound_version_id=bound_version_id or system.current_version_id,
            evidence_type=evidence_type,
            filename=filename,
            media_type=media_type,
            uri=uri,
            sha256=digest,
            bytes_size=len(content),
            collector_version=self.settings.collector_version or COLLECTOR_VERSION,
            verification_status=verification,
            collected_at=collected_at or now,
            created_at=now,
        )
        self.session.add(row)
        await self.audit.append(
            tenant_id=principal.tenant_id,
            aggregate_id=system.id,
            event_type="EvidenceAttached",
            actor=_actor(principal),
            payload={
                "evidenceId": evidence_id,
                "type": evidence_type,
                "sha256": digest,
                "boundVersionId": row.bound_version_id,
                "verificationStatus": verification,
            },
        )
        await self.session.commit()
        await self.session.refresh(row)
        return row

    async def verify_evidence(
        self, principal: Principal, system_id: str, evidence_id: str
    ) -> EvidenceArtifactModel:
        await self.get_system(principal, system_id)
        row = await self.session.scalar(
            select(EvidenceArtifactModel).where(
                EvidenceArtifactModel.id == evidence_id,
                EvidenceArtifactModel.tenant_id == principal.tenant_id,
                EvidenceArtifactModel.system_id == system_id,
            )
        )
        if row is None:
            raise NotFoundError(evidence_id)
        key = f"{principal.tenant_id}/{system_id}/{row.id}"
        stored = await self.object_store.get(key)
        row.verification_status = "VERIFIED" if _sha256(stored) == row.sha256 else "FAIL"
        await self.audit.append(
            tenant_id=principal.tenant_id,
            aggregate_id=system_id,
            event_type="EvidenceVerified",
            actor=_actor(principal),
            payload={"evidenceId": row.id, "verificationStatus": row.verification_status},
        )
        await self.session.commit()
        await self.session.refresh(row)
        return row

    async def cut_version(self, principal: Principal, system_id: str) -> AISystemModel:
        system = await self.get_system(principal, system_id)
        previous = system.current_version_id
        now = utcnow()
        revoked_ids = await self._revoke_active_authorizations(
            principal, system, reason="ASSET_VERSION_CREATED"
        )
        await self._revoke_open_exceptions(principal, system, now, reason="ASSET_VERSION_CREATED")
        await self._close_open_case(principal, system, now, reason="ASSET_VERSION_CREATED")
        system.current_version_id = new_id("ver")
        system.updated_at = now
        await self.audit.append(
            tenant_id=principal.tenant_id,
            aggregate_id=system.id,
            event_type="AssetVersionCreated",
            actor=_actor(principal),
            payload={
                "previousVersionId": previous,
                "versionId": system.current_version_id,
                "revokedAuthorizationIds": revoked_ids,
            },
        )
        await self.session.commit()
        await self.session.refresh(system)
        return system

    async def evaluate_gate(
        self,
        principal: Principal,
        system_id: str,
        *,
        environment: str | None = None,
        evidence_stale: bool = False,
        cloud: str = "local",
        region: str | None = None,
        audience: str = "cicd",
    ) -> GateResult:
        system = await self.get_system(principal, system_id)
        assessment = await self.latest_assessment(principal, system_id)
        approvals = await self.list_approvals(principal, system_id)
        approval_map = _approval_map(approvals)
        artifacts = await self.list_evidence(principal, system_id)
        posture = assess_controls(system, assessment, artifacts)
        evidence_doc = controls_to_policy_document(posture)
        evidence_doc["stale"] = bool(evidence_stale or evidence_doc["stale"])
        target_environment = environment or system.environment
        now = utcnow()
        await self._expire_stale_exceptions(principal, system, now)
        exception_rows = await self.list_exceptions(principal, system_id)
        incident_rows = await self.list_incidents(principal, system_id)
        document = {
            "asset": {
                "id": system.id,
                "risk_band": assessment.risk_band if assessment else None,
                "data_classification": system.data_classification,
                "autonomy_level": system.autonomy_level,
                "uses_customer_decision": bool(system.registration.get("usesCustomerDecision")),
                "status": system.status,
                "environment": target_environment,
                "version_id": system.current_version_id,
            },
            "approvals": approval_map,
            "human_oversight": {"controls": system.human_oversight},
            "risk": {
                "band": assessment.risk_band if assessment else None,
                "score": assessment.score if assessment else None,
                "confidence": assessment.confidence if assessment else None,
            },
            "evidence": evidence_doc,
            "exceptions": exceptions_to_policy_document(
                exception_rows,
                current_version_id=system.current_version_id,
                now=now,
            ),
            "incidents": open_incidents_to_policy_document(incident_rows),
        }
        evaluation: PolicyEvaluation = await self.policy_engine.evaluate_deployment(document)
        row = PolicyDecisionModel(
            id=new_id("pdec"),
            tenant_id=principal.tenant_id,
            system_id=system.id,
            outcome=evaluation.outcome,
            policy_bundle=evaluation.policy_bundle,
            reasons=[reason.__dict__ for reason in evaluation.reasons],
            required_actions=evaluation.required_actions,
            policy_digest=evaluation.policy_digest,
            input_digest=_digest(document),
            decided_at=now,
        )
        parts = build_snapshot_parts(
            asset_version_id=system.current_version_id,
            environment=target_environment,
            risk={
                "band": assessment.risk_band if assessment else None,
                "score": assessment.score if assessment else None,
                "confidence": assessment.confidence if assessment else None,
                "engineVersion": assessment.engine_version if assessment else None,
            },
            controls=_control_records(posture),
            evidence_hashes=[artifact.sha256 for artifact in artifacts],
            approvals=approval_map,
            policy_bundle=evaluation.policy_bundle,
            policy_digest=evaluation.policy_digest,
            engine_versions={
                "risk": self.settings.risk_engine_version,
                "policy": evaluation.policy_bundle,
                "collector": self.settings.collector_version or COLLECTOR_VERSION,
            },
            exceptions=exception_fingerprint_records(
                exception_rows,
                current_version_id=system.current_version_id,
                now=now,
            ),
            incidents=incident_fingerprint_records(incident_rows),
        )
        fingerprint = governance_fingerprint(parts)
        snapshot = GovernanceDecisionModel(
            id=new_id("snap"),
            tenant_id=principal.tenant_id,
            system_id=system.id,
            policy_decision_id=row.id,
            outcome=evaluation.outcome,
            asset_version_id=system.current_version_id,
            fingerprint=fingerprint,
            snapshot=parts,
            created_at=now,
        )
        system.status = _status_after_gate(system.status, evaluation.outcome)
        system.updated_at = now
        self.session.add(row)
        self.session.add(snapshot)
        authorization: DeploymentAuthorizationModel | None = None
        if evaluation.outcome == "ALLOW":
            authorization = self._issue_authorization(
                principal,
                system,
                snapshot,
                environment=target_environment,
                cloud=cloud,
                region=region,
                audience=audience,
                issued_at=now,
            )
            self.session.add(authorization)
        await self.audit.append(
            tenant_id=principal.tenant_id,
            aggregate_id=system.id,
            event_type="DeploymentGateEvaluated",
            actor=_actor(principal),
            payload={
                "decisionId": row.id,
                "snapshotId": snapshot.id,
                "outcome": evaluation.outcome,
                "fingerprint": fingerprint,
                "authorizationId": authorization.id if authorization else None,
                "reasons": [reason.code for reason in evaluation.reasons],
                "policyBundle": evaluation.policy_bundle,
            },
        )
        if authorization is not None:
            await self.audit.append(
                tenant_id=principal.tenant_id,
                aggregate_id=system.id,
                event_type="DeploymentAuthorizationIssued",
                actor=_actor(principal),
                payload={
                    "authorizationId": authorization.id,
                    "snapshotId": snapshot.id,
                    "fingerprint": fingerprint,
                    "expiresAt": authorization.expires_at.isoformat(),
                },
            )
        await self._sync_workflow_case(
            principal,
            system,
            decision=row,
            snapshot=snapshot,
            assessment=assessment,
            now=now,
        )
        await self.session.commit()
        await self.session.refresh(row)
        await self.session.refresh(snapshot)
        if authorization is not None:
            await self.session.refresh(authorization)
        return GateResult(decision=row, snapshot=snapshot, authorization=authorization)

    async def verify_authorization(
        self,
        principal: Principal,
        system_id: str,
        authorization_id: str,
        *,
        presented_signature: str | None = None,
        consume: bool = False,
    ) -> tuple[DeploymentAuthorizationModel, AuthorizationCheck]:
        system = await self.get_system(principal, system_id)
        row = await self.get_authorization(principal, system_id, authorization_id)
        check = evaluate_authorization(
            secret=self.settings.authorization_secret,
            authorization_id=row.id,
            fingerprint=row.fingerprint,
            nonce=row.nonce,
            expires_at=row.expires_at,
            signature=row.signature,
            presented_signature=presented_signature,
            now=utcnow(),
            revoked_at=row.revoked_at,
            consumed_at=row.consumed_at,
            bound_version_id=row.asset_version_id,
            current_version_id=system.current_version_id,
        )
        if check.outcome == "ALLOW" and consume:
            row.consumed_at = utcnow()
        await self.audit.append(
            tenant_id=principal.tenant_id,
            aggregate_id=system.id,
            event_type="DeploymentAuthorizationVerified",
            actor=_actor(principal),
            payload={
                "authorizationId": row.id,
                "outcome": check.outcome,
                "reasons": check.reasons,
                "consumed": bool(consume and check.outcome == "ALLOW"),
            },
        )
        await self.session.commit()
        await self.session.refresh(row)
        return row, check

    async def revoke_authorization(
        self, principal: Principal, system_id: str, authorization_id: str
    ) -> DeploymentAuthorizationModel:
        row = await self.get_authorization(principal, system_id, authorization_id)
        if row.revoked_at is None:
            row.revoked_at = utcnow()
            await self.audit.append(
                tenant_id=principal.tenant_id,
                aggregate_id=system_id,
                event_type="DeploymentAuthorizationRevoked",
                actor=_actor(principal),
                payload={"authorizationId": row.id, "fingerprint": row.fingerprint},
            )
            await self.session.commit()
            await self.session.refresh(row)
        return row

    async def request_exception(
        self,
        principal: Principal,
        system_id: str,
        *,
        violation_code: str,
        justification: str,
        expires_at: datetime | None = None,
        control_id: str | None = None,
    ) -> ExceptionModel:
        system = await self.get_system(principal, system_id)
        now = utcnow()
        await self._expire_stale_exceptions(principal, system, now)
        assessment = await self.latest_assessment(principal, system_id)
        band = assessment.risk_band if assessment else None
        expiry = expires_at or default_expires_at(now, band)
        try:
            validate_exception_request(
                violation_code=violation_code,
                justification=justification,
                expires_at=expiry,
                now=now,
                risk_band=band,
            )
        except ExceptionRuleError as exc:
            raise ExceptionRejectedError(exc.detail, exc.code) from exc
        case = await self.open_case(principal, system.id)
        if case is None:
            case = WorkflowCaseModel(
                id=new_id("case"),
                tenant_id=principal.tenant_id,
                system_id=system.id,
                decision_id=None,
                snapshot_id=None,
                case_type="EXCEPTION",
                status="OPEN",
                risk_band=band,
                reason_codes=[violation_code],
                opened_at=now,
                due_at=compute_due_at(now, band),
                closed_at=None,
            )
            self.session.add(case)
            await self.audit.append(
                tenant_id=principal.tenant_id,
                aggregate_id=system.id,
                event_type="WorkflowCaseOpened",
                actor=_actor(principal),
                payload={
                    "caseId": case.id,
                    "reasonCodes": [violation_code],
                    "dueAt": case.due_at.isoformat(),
                },
            )
        row = ExceptionModel(
            id=new_id("exc"),
            tenant_id=principal.tenant_id,
            system_id=system.id,
            case_id=case.id,
            violation_code=violation_code,
            control_id=control_id,
            bound_version_id=system.current_version_id,
            justification=justification.strip(),
            status="REQUESTED",
            requested_by=principal.actor_id,
            granted_by=None,
            requested_at=now,
            granted_at=None,
            expires_at=expiry,
            revoked_at=None,
        )
        self.session.add(row)
        await self.audit.append(
            tenant_id=principal.tenant_id,
            aggregate_id=system.id,
            event_type="ExceptionRequested",
            actor=_actor(principal),
            payload={
                "exceptionId": row.id,
                "violationCode": violation_code,
                "expiresAt": expiry.isoformat(),
                "caseId": case.id,
            },
        )
        await self.session.commit()
        await self.session.refresh(row)
        return row

    async def grant_exception(
        self, principal: Principal, system_id: str, exception_id: str
    ) -> ExceptionModel:
        system = await self.get_system(principal, system_id)
        if not principal.has_role(*EXCEPTION_GRANT_ROLES):
            raise SegregationOfDutiesError("principal lacks reviewer role to grant exceptions")
        row = await self.get_exception(principal, system_id, exception_id)
        if principal.actor_id == row.requested_by:
            raise SegregationOfDutiesError("requester cannot grant their own exception")
        if row.status != "REQUESTED":
            raise ExceptionRejectedError("exception is not pending grant")
        now = utcnow()
        if as_utc(row.expires_at) <= now:
            raise ExceptionRejectedError("exception has already expired")
        row.status = "GRANTED"
        row.granted_by = principal.actor_id
        row.granted_at = now
        await self.audit.append(
            tenant_id=principal.tenant_id,
            aggregate_id=system.id,
            event_type="ExceptionGranted",
            actor=_actor(principal),
            payload={
                "exceptionId": row.id,
                "violationCode": row.violation_code,
                "expiresAt": row.expires_at.isoformat(),
            },
        )
        await self.session.commit()
        await self.session.refresh(row)
        return row

    async def deny_exception(
        self, principal: Principal, system_id: str, exception_id: str
    ) -> ExceptionModel:
        if not principal.has_role(*EXCEPTION_GRANT_ROLES):
            raise SegregationOfDutiesError("principal lacks reviewer role to deny exceptions")
        row = await self.get_exception(principal, system_id, exception_id)
        if row.status != "REQUESTED":
            raise ExceptionRejectedError("exception is not pending review")
        row.status = "DENIED"
        await self.audit.append(
            tenant_id=principal.tenant_id,
            aggregate_id=system_id,
            event_type="ExceptionDenied",
            actor=_actor(principal),
            payload={"exceptionId": row.id, "violationCode": row.violation_code},
        )
        await self.session.commit()
        await self.session.refresh(row)
        return row

    async def revoke_exception(
        self, principal: Principal, system_id: str, exception_id: str
    ) -> ExceptionModel:
        system = await self.get_system(principal, system_id)
        if not principal.has_role(*EXCEPTION_GRANT_ROLES):
            raise SegregationOfDutiesError("principal lacks reviewer role to revoke exceptions")
        row = await self.get_exception(principal, system_id, exception_id)
        if row.status != "GRANTED":
            raise ExceptionRejectedError("only a granted exception can be revoked")
        now = utcnow()
        row.status = "REVOKED"
        row.revoked_at = now
        await self._revoke_active_authorizations(principal, system, reason="EXCEPTION_REVOKED")
        await self.audit.append(
            tenant_id=principal.tenant_id,
            aggregate_id=system.id,
            event_type="ExceptionRevoked",
            actor=_actor(principal),
            payload={"exceptionId": row.id, "violationCode": row.violation_code},
        )
        await self.session.commit()
        await self.session.refresh(row)
        return row

    async def record_finding(
        self,
        principal: Principal,
        system_id: str,
        *,
        finding_type: str,
        severity: str,
        summary: str,
        detector: str = "HUMAN",
    ) -> FindingModel:
        system = await self.get_system(principal, system_id)
        try:
            validate_finding(finding_type=finding_type, severity=severity, summary=summary)
        except FindingRuleError as exc:
            raise FindingRejectedError(exc.detail, exc.code) from exc
        now = utcnow()
        row = FindingModel(
            id=new_id("fnd"),
            tenant_id=principal.tenant_id,
            system_id=system.id,
            incident_id=None,
            bound_version_id=system.current_version_id,
            finding_type=finding_type,
            severity=severity,
            summary=summary.strip(),
            detector=(detector or "HUMAN").strip() or "HUMAN",
            status="OPEN",
            recorded_by=principal.actor_id,
            recorded_at=now,
            resolved_at=None,
            dismissed_at=None,
        )
        self.session.add(row)
        await self.audit.append(
            tenant_id=principal.tenant_id,
            aggregate_id=system.id,
            event_type="FindingRecorded",
            actor=_actor(principal),
            payload={
                "findingId": row.id,
                "findingType": finding_type,
                "severity": severity,
                "boundVersionId": system.current_version_id,
            },
        )
        if auto_promotes(severity):
            await self._promote_to_incident(principal, system, row, now)
        await self.session.commit()
        await self.session.refresh(row)
        return row

    async def promote_finding(
        self, principal: Principal, system_id: str, finding_id: str
    ) -> FindingModel:
        system = await self.get_system(principal, system_id)
        if not principal.has_role(*FINDING_REVIEW_ROLES):
            raise SegregationOfDutiesError("principal lacks reviewer role to promote findings")
        row = await self.get_finding(principal, system_id, finding_id)
        if row.status != "OPEN":
            raise FindingRejectedError("only an open finding can be promoted")
        now = utcnow()
        await self._promote_to_incident(principal, system, row, now)
        await self.session.commit()
        await self.session.refresh(row)
        return row

    async def dismiss_finding(
        self, principal: Principal, system_id: str, finding_id: str
    ) -> FindingModel:
        if not principal.has_role(*FINDING_REVIEW_ROLES):
            raise SegregationOfDutiesError("principal lacks reviewer role to dismiss findings")
        row = await self.get_finding(principal, system_id, finding_id)
        if row.status != "OPEN":
            raise FindingRejectedError(
                "promoted findings cannot be dismissed; resolve the incident"
                if row.status == "PROMOTED"
                else "only an open finding can be dismissed"
            )
        now = utcnow()
        row.status = "DISMISSED"
        row.dismissed_at = now
        await self.audit.append(
            tenant_id=principal.tenant_id,
            aggregate_id=system_id,
            event_type="FindingDismissed",
            actor=_actor(principal),
            payload={"findingId": row.id, "findingType": row.finding_type},
        )
        await self.session.commit()
        await self.session.refresh(row)
        return row

    async def resolve_incident(
        self, principal: Principal, system_id: str, incident_id: str
    ) -> IncidentModel:
        if not principal.has_role(*FINDING_REVIEW_ROLES):
            raise SegregationOfDutiesError("principal lacks reviewer role to resolve incidents")
        incident = await self.get_incident(principal, system_id, incident_id)
        if incident.status != "OPEN":
            raise FindingRejectedError("only an open incident can be resolved")
        now = utcnow()
        incident.status = "RESOLVED"
        incident.resolved_by = principal.actor_id
        incident.resolved_at = now
        linked = await self.session.scalars(
            select(FindingModel).where(
                FindingModel.tenant_id == principal.tenant_id,
                FindingModel.system_id == system_id,
                FindingModel.incident_id == incident.id,
            )
        )
        for finding in linked:
            finding.status = "RESOLVED"
            finding.resolved_at = now
        await self.audit.append(
            tenant_id=principal.tenant_id,
            aggregate_id=system_id,
            event_type="IncidentResolved",
            actor=_actor(principal),
            payload={"incidentId": incident.id, "severity": incident.severity},
        )
        await self.session.commit()
        await self.session.refresh(incident)
        return incident

    async def _promote_to_incident(
        self,
        principal: Principal,
        system: AISystemModel,
        finding: FindingModel,
        now: datetime,
    ) -> IncidentModel:
        incident = IncidentModel(
            id=new_id("inc"),
            tenant_id=principal.tenant_id,
            system_id=system.id,
            severity=finding.severity,
            status="OPEN",
            title=incident_title(finding.finding_type, finding.severity),
            summary=finding.summary,
            opened_by=principal.actor_id,
            resolved_by=None,
            opened_at=now,
            resolved_at=None,
        )
        self.session.add(incident)
        finding.status = "PROMOTED"
        finding.incident_id = incident.id
        system.status = "BLOCKED"
        system.updated_at = now
        await self._revoke_active_authorizations(principal, system, reason="RUNTIME_INCIDENT")
        await self._revoke_open_exceptions(principal, system, now, reason="RUNTIME_INCIDENT")
        await self._open_incident_case(principal, system, incident=incident, now=now)
        await self.audit.append(
            tenant_id=principal.tenant_id,
            aggregate_id=system.id,
            event_type="IncidentOpened",
            actor=_actor(principal),
            payload={
                "incidentId": incident.id,
                "findingId": finding.id,
                "severity": incident.severity,
            },
        )
        await self.audit.append(
            tenant_id=principal.tenant_id,
            aggregate_id=system.id,
            event_type="FindingPromoted",
            actor=_actor(principal),
            payload={"findingId": finding.id, "incidentId": incident.id},
        )
        return incident

    async def _open_incident_case(
        self,
        principal: Principal,
        system: AISystemModel,
        *,
        incident: IncidentModel,
        now: datetime,
    ) -> WorkflowCaseModel:
        open_case = await self.open_case(principal, system.id)
        codes = ["RUNTIME_INCIDENT"]
        if open_case is None:
            open_case = WorkflowCaseModel(
                id=new_id("case"),
                tenant_id=principal.tenant_id,
                system_id=system.id,
                decision_id=None,
                snapshot_id=None,
                case_type="INCIDENT",
                status="OPEN",
                risk_band=incident.severity,
                reason_codes=codes,
                opened_at=now,
                due_at=compute_due_at(now, incident.severity),
                closed_at=None,
            )
            self.session.add(open_case)
            await self.audit.append(
                tenant_id=principal.tenant_id,
                aggregate_id=system.id,
                event_type="WorkflowCaseOpened",
                actor=_actor(principal),
                payload={
                    "caseId": open_case.id,
                    "reasonCodes": codes,
                    "dueAt": open_case.due_at.isoformat(),
                    "caseType": "INCIDENT",
                },
            )
            return open_case
        open_case.case_type = "INCIDENT"
        open_case.reason_codes = list(dict.fromkeys([*(open_case.reason_codes or []), *codes]))
        open_case.risk_band = incident.severity
        await self.audit.append(
            tenant_id=principal.tenant_id,
            aggregate_id=system.id,
            event_type="WorkflowCaseUpdated",
            actor=_actor(principal),
            payload={
                "caseId": open_case.id,
                "reasonCodes": open_case.reason_codes,
                "caseType": "INCIDENT",
            },
        )
        return open_case

    def _issue_authorization(
        self,
        principal: Principal,
        system: AISystemModel,
        snapshot: GovernanceDecisionModel,
        *,
        environment: str,
        cloud: str,
        region: str | None,
        audience: str,
        issued_at: datetime,
    ) -> DeploymentAuthorizationModel:
        authorization_id = new_id("authz")
        nonce = new_id("nce")
        ttl = max(0, int(self.settings.authorization_ttl_seconds))
        expires_at = issued_at + timedelta(seconds=ttl)
        signature = sign_authorization(
            secret=self.settings.authorization_secret,
            authorization_id=authorization_id,
            fingerprint=snapshot.fingerprint,
            nonce=nonce,
            expires_at=expires_at,
        )
        return DeploymentAuthorizationModel(
            id=authorization_id,
            tenant_id=principal.tenant_id,
            system_id=system.id,
            decision_id=snapshot.id,
            asset_version_id=snapshot.asset_version_id,
            environment=environment,
            cloud=cloud,
            region=region,
            audience=audience,
            nonce=nonce,
            fingerprint=snapshot.fingerprint,
            signature=signature,
            issued_at=issued_at,
            expires_at=expires_at,
        )

    async def _revoke_active_authorizations(
        self, principal: Principal, system: AISystemModel, *, reason: str
    ) -> list[str]:
        result = await self.session.scalars(
            select(DeploymentAuthorizationModel).where(
                DeploymentAuthorizationModel.tenant_id == principal.tenant_id,
                DeploymentAuthorizationModel.system_id == system.id,
                DeploymentAuthorizationModel.revoked_at.is_(None),
            )
        )
        now = utcnow()
        revoked_ids: list[str] = []
        for row in result:
            row.revoked_at = now
            revoked_ids.append(row.id)
        if revoked_ids:
            await self.audit.append(
                tenant_id=principal.tenant_id,
                aggregate_id=system.id,
                event_type="DeploymentAuthorizationRevoked",
                actor=_actor(principal),
                payload={"authorizationIds": revoked_ids, "reason": reason},
            )
        return revoked_ids

    async def _expire_stale_exceptions(
        self, principal: Principal, system: AISystemModel, now: datetime
    ) -> list[str]:
        result = await self.session.scalars(
            select(ExceptionModel).where(
                ExceptionModel.tenant_id == principal.tenant_id,
                ExceptionModel.system_id == system.id,
                ExceptionModel.status == "GRANTED",
            )
        )
        expired_ids: list[str] = []
        for row in result:
            if as_utc(row.expires_at) <= now:
                row.status = "EXPIRED"
                expired_ids.append(row.id)
        if expired_ids:
            await self._revoke_active_authorizations(principal, system, reason="EXCEPTION_EXPIRED")
            await self.audit.append(
                tenant_id=principal.tenant_id,
                aggregate_id=system.id,
                event_type="ExceptionExpired",
                actor=_actor(principal),
                payload={"exceptionIds": expired_ids},
            )
        return expired_ids

    async def _revoke_open_exceptions(
        self, principal: Principal, system: AISystemModel, now: datetime, *, reason: str
    ) -> list[str]:
        result = await self.session.scalars(
            select(ExceptionModel).where(
                ExceptionModel.tenant_id == principal.tenant_id,
                ExceptionModel.system_id == system.id,
                ExceptionModel.status.in_(("REQUESTED", "GRANTED")),
            )
        )
        revoked_ids: list[str] = []
        for row in result:
            row.status = "REVOKED"
            row.revoked_at = now
            revoked_ids.append(row.id)
        if revoked_ids:
            await self.audit.append(
                tenant_id=principal.tenant_id,
                aggregate_id=system.id,
                event_type="ExceptionRevoked",
                actor=_actor(principal),
                payload={"exceptionIds": revoked_ids, "reason": reason},
            )
        return revoked_ids

    async def _close_open_case(
        self, principal: Principal, system: AISystemModel, now: datetime, *, reason: str
    ) -> None:
        case = await self.open_case(principal, system.id)
        if case is None:
            return
        case.status = "CLOSED"
        case.closed_at = now
        await self.audit.append(
            tenant_id=principal.tenant_id,
            aggregate_id=system.id,
            event_type="WorkflowCaseClosed",
            actor=_actor(principal),
            payload={"caseId": case.id, "reason": reason},
        )

    async def _sync_workflow_case(
        self,
        principal: Principal,
        system: AISystemModel,
        *,
        decision: PolicyDecisionModel,
        snapshot: GovernanceDecisionModel,
        assessment: RiskAssessmentModel | None,
        now: datetime,
    ) -> None:
        codes = [item["code"] for item in decision.reasons]
        band = assessment.risk_band if assessment else None
        open_case = await self.open_case(principal, system.id)
        if decision.outcome in {"BLOCK", "REVIEW"}:
            if open_case is None:
                open_case = WorkflowCaseModel(
                    id=new_id("case"),
                    tenant_id=principal.tenant_id,
                    system_id=system.id,
                    decision_id=decision.id,
                    snapshot_id=snapshot.id,
                    case_type="GATE_REVIEW",
                    status="OPEN",
                    risk_band=band,
                    reason_codes=codes,
                    opened_at=now,
                    due_at=compute_due_at(now, band),
                    closed_at=None,
                )
                self.session.add(open_case)
                await self.audit.append(
                    tenant_id=principal.tenant_id,
                    aggregate_id=system.id,
                    event_type="WorkflowCaseOpened",
                    actor=_actor(principal),
                    payload={
                        "caseId": open_case.id,
                        "outcome": decision.outcome,
                        "reasonCodes": codes,
                        "dueAt": open_case.due_at.isoformat(),
                    },
                )
                return
            open_case.decision_id = decision.id
            open_case.snapshot_id = snapshot.id
            open_case.reason_codes = codes
            if band:
                open_case.risk_band = band
            await self.audit.append(
                tenant_id=principal.tenant_id,
                aggregate_id=system.id,
                event_type="WorkflowCaseUpdated",
                actor=_actor(principal),
                payload={"caseId": open_case.id, "reasonCodes": codes, "outcome": decision.outcome},
            )
            return
        if decision.outcome == "ALLOW" and open_case is not None:
            open_case.status = "CLOSED"
            open_case.closed_at = now
            open_case.decision_id = decision.id
            open_case.snapshot_id = snapshot.id
            await self.audit.append(
                tenant_id=principal.tenant_id,
                aggregate_id=system.id,
                event_type="WorkflowCaseClosed",
                actor=_actor(principal),
                payload={"caseId": open_case.id, "outcome": "ALLOW"},
            )


def _actor(principal: Principal) -> dict[str, str]:
    return {"type": principal.actor_type, "id": principal.actor_id, "name": principal.display_name}


def _owner_actor(system: AISystemModel) -> str | None:
    return None


def _control_records(posture: list[ControlAssessment]) -> list[dict[str, Any]]:
    return [
        {
            "controlId": item.control_id,
            "evidenceType": item.evidence_type,
            "status": item.status,
            "evidenceId": item.evidence_id,
            "sha256": item.sha256,
        }
        for item in posture
    ]


def _approval_map(rows: list[ApprovalModel]) -> dict[str, bool]:
    latest: dict[str, ApprovalModel] = {}
    for row in rows:
        latest[row.function] = row
    return {function: row.approved for function, row in latest.items()}


def _status_after_assessment(band: str, confidence: float) -> str:
    if confidence < 0.7 or band in {"HIGH", "CRITICAL"}:
        return "REVIEW_REQUIRED"
    return "APPROVED"


def _status_after_gate(current: str, outcome: str) -> str:
    if outcome == "ALLOW":
        return "APPROVED"
    if outcome == "BLOCK":
        return "BLOCKED"
    if current == "DRAFT":
        return "REVIEW_REQUIRED"
    return current

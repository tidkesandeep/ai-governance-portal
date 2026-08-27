from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aigov.config import Settings, get_settings
from aigov.domains.audit.service import AuditLog
from aigov.domains.evidence.service import (
    COLLECTOR_VERSION,
    ControlAssessment,
    assess_controls,
    controls_to_policy_document,
    reject_upload,
)
from aigov.domains.identity.principal import Principal
from aigov.domains.policy.engine import PolicyEngine, PolicyEvaluation
from aigov.domains.risk.engine import assess as assess_risk
from aigov.infrastructure.ids import new_id, utcnow
from aigov.infrastructure.models import (
    AISystemModel,
    ApprovalModel,
    EvidenceArtifactModel,
    PolicyDecisionModel,
    RiskAssessmentModel,
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


APPROVER_ROLES = {
    "privacy": ("privacy",),
    "security": ("security",),
    "risk": ("risk_reviewer",),
    "owner": ("owner",),
}


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
        system.current_version_id = new_id("ver")
        system.updated_at = utcnow()
        await self.audit.append(
            tenant_id=principal.tenant_id,
            aggregate_id=system.id,
            event_type="AssetVersionCreated",
            actor=_actor(principal),
            payload={"previousVersionId": previous, "versionId": system.current_version_id},
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
    ) -> PolicyDecisionModel:
        system = await self.get_system(principal, system_id)
        assessment = await self.latest_assessment(principal, system_id)
        approvals = await self.list_approvals(principal, system_id)
        approval_map = _approval_map(approvals)
        artifacts = await self.list_evidence(principal, system_id)
        posture = assess_controls(system, assessment, artifacts)
        evidence_doc = controls_to_policy_document(posture)
        evidence_doc["stale"] = bool(evidence_stale or evidence_doc["stale"])
        document = {
            "asset": {
                "id": system.id,
                "risk_band": assessment.risk_band if assessment else None,
                "data_classification": system.data_classification,
                "autonomy_level": system.autonomy_level,
                "uses_customer_decision": bool(system.registration.get("usesCustomerDecision")),
                "status": system.status,
                "environment": environment or system.environment,
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
        }
        evaluation: PolicyEvaluation = await self.policy_engine.evaluate_deployment(document)
        now = utcnow()
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
        system.status = _status_after_gate(system.status, evaluation.outcome)
        system.updated_at = now
        self.session.add(row)
        await self.audit.append(
            tenant_id=principal.tenant_id,
            aggregate_id=system.id,
            event_type="DeploymentGateEvaluated",
            actor=_actor(principal),
            payload={
                "decisionId": row.id,
                "outcome": evaluation.outcome,
                "reasons": [reason.code for reason in evaluation.reasons],
                "policyBundle": evaluation.policy_bundle,
            },
        )
        await self.session.commit()
        await self.session.refresh(row)
        return row


def _actor(principal: Principal) -> dict[str, str]:
    return {"type": principal.actor_type, "id": principal.actor_id, "name": principal.display_name}


def _owner_actor(system: AISystemModel) -> str | None:
    return None


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

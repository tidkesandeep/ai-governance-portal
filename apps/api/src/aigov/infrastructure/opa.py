from __future__ import annotations

from typing import Any

import httpx

from aigov.domains.policy.engine import (
    ACTION_BUNDLE,
    ACTION_DIGEST,
    POLICY_BUNDLE,
    POLICY_DIGEST,
    PolicyEvaluation,
    PolicyReason,
    evaluate_action_document,
    evaluate_deployment_document,
)


class OPAPolicyEngine:
    def __init__(self, base_url: str, timeout_s: float = 5.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_s

    async def evaluate_deployment(self, document: dict[str, Any]) -> PolicyEvaluation:
        url = f"{self._base_url}/v1/data/aigov/deployment"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(url, json={"input": document})
                response.raise_for_status()
                result = (response.json() or {}).get("result") or {}
        except httpx.HTTPError:
            # Fail closed: if OPA cannot be reached, still apply the signed-in rule set.
            embedded = evaluate_deployment_document(document)
            reasons = list(embedded.reasons)
            reasons.insert(
                0,
                PolicyReason(
                    "POLICY_ENGINE_UNAVAILABLE",
                    "HIGH",
                    "OPA was unreachable; gate failed closed using the embedded bundle",
                ),
            )
            return PolicyEvaluation(
                outcome="BLOCK",
                reasons=reasons,
                required_actions=["restore policy engine"] + embedded.required_actions,
                policy_bundle=POLICY_BUNDLE,
                policy_digest=POLICY_DIGEST,
            )

        raw_violations = result.get("violation") or []
        reasons = [
            PolicyReason(
                code=item.get("code", "POLICY_VIOLATION"),
                severity=item.get("severity", "HIGH"),
                message=item.get("message", ""),
            )
            for item in raw_violations
        ]
        outcome = result.get("outcome") or ("ALLOW" if not reasons else "BLOCK")
        actions = list(result.get("required_actions") or [])
        return PolicyEvaluation(
            outcome=outcome,
            reasons=reasons,
            required_actions=actions,
            policy_bundle=POLICY_BUNDLE,
            policy_digest=POLICY_DIGEST,
        )

    async def evaluate_action(self, document: dict[str, Any]) -> PolicyEvaluation:
        url = f"{self._base_url}/v1/data/aigov/action"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(url, json={"input": document})
                response.raise_for_status()
                result = (response.json() or {}).get("result") or {}
        except httpx.HTTPError:
            embedded = evaluate_action_document(document)
            reasons = list(embedded.reasons)
            reasons.insert(
                0,
                PolicyReason(
                    "POLICY_ENGINE_UNAVAILABLE",
                    "HIGH",
                    "OPA was unreachable; action gate failed closed using the embedded bundle",
                ),
            )
            return PolicyEvaluation(
                outcome="DENY",
                reasons=reasons,
                required_actions=["restore policy engine"] + embedded.required_actions,
                policy_bundle=ACTION_BUNDLE,
                policy_digest=ACTION_DIGEST,
            )

        raw_violations = result.get("violation") or []
        reasons = [
            PolicyReason(
                code=item.get("code", "POLICY_VIOLATION"),
                severity=item.get("severity", "HIGH"),
                message=item.get("message", ""),
            )
            for item in raw_violations
        ]
        outcome = result.get("outcome") or ("ALLOW" if not reasons else "DENY")
        actions = list(result.get("required_actions") or [])
        return PolicyEvaluation(
            outcome=outcome,
            reasons=reasons,
            required_actions=actions,
            policy_bundle=ACTION_BUNDLE,
            policy_digest=ACTION_DIGEST,
        )

from aigov.domains.policy.engine import evaluate_action_document, evaluate_deployment_document


def _base(**overrides):
    document = {
        "asset": {
            "risk_band": "LOW",
            "data_classification": "INTERNAL",
            "autonomy_level": "HUMAN_IN_LOOP",
            "uses_customer_decision": False,
        },
        "approvals": {},
        "human_oversight": {"controls": []},
        "risk": {"band": "LOW", "confidence": 0.9},
        "evidence": {"stale": False},
    }
    document.update(overrides)
    return document


def test_low_risk_internal_allows() -> None:
    result = evaluate_deployment_document(_base())
    assert result.outcome == "ALLOW"
    assert result.reasons == []


def test_high_risk_without_privacy_blocks() -> None:
    result = evaluate_deployment_document(
        _base(
            asset={
                "risk_band": "HIGH",
                "data_classification": "PII",
                "autonomy_level": "ASSISTIVE",
                "uses_customer_decision": True,
            },
            approvals={"security": True},
            risk={"band": "HIGH", "confidence": 0.96},
        )
    )
    assert result.outcome == "BLOCK"
    codes = {reason.code for reason in result.reasons}
    assert "MISSING_PRIVACY_APPROVAL" in codes
    assert "MISSING_RISK_APPROVAL" in codes


def test_stale_evidence_reviews() -> None:
    result = evaluate_deployment_document(_base(evidence={"stale": True}))
    assert result.outcome == "REVIEW"
    assert result.reasons[0].code == "STALE_EVIDENCE"


def test_autonomous_without_oversight_blocks() -> None:
    result = evaluate_deployment_document(
        _base(
            asset={
                "risk_band": "MEDIUM",
                "data_classification": "INTERNAL",
                "autonomy_level": "AUTONOMOUS",
                "uses_customer_decision": False,
            },
            risk={"band": "MEDIUM", "confidence": 0.9},
        )
    )
    assert result.outcome == "BLOCK"
    assert result.reasons[0].code == "MISSING_HUMAN_OVERSIGHT"


def test_unknown_required_evidence_blocks() -> None:
    result = evaluate_deployment_document(
        _base(
            asset={
                "risk_band": "HIGH",
                "data_classification": "INTERNAL",
                "autonomy_level": "HUMAN_IN_LOOP",
                "uses_customer_decision": False,
            },
            approvals={"security": True},
            risk={"band": "HIGH", "confidence": 0.9},
            evidence={
                "stale": False,
                "controls": [
                    {
                        "id": "CTRL-ML-PERF-001",
                        "type": "EVALUATION_RUN",
                        "required": True,
                        "status": "UNKNOWN",
                    }
                ],
            },
        )
    )
    assert result.outcome == "BLOCK"
    assert any(reason.code == "MISSING_REQUIRED_EVIDENCE" for reason in result.reasons)


def test_stale_required_evidence_blocks_high() -> None:
    result = evaluate_deployment_document(
        _base(
            asset={
                "risk_band": "HIGH",
                "data_classification": "INTERNAL",
                "autonomy_level": "HUMAN_IN_LOOP",
                "uses_customer_decision": False,
            },
            approvals={"security": True},
            risk={"band": "HIGH", "confidence": 0.9},
            evidence={
                "stale": True,
                "controls": [
                    {
                        "id": "CTRL-ML-PERF-001",
                        "type": "EVALUATION_RUN",
                        "required": True,
                        "status": "STALE",
                    }
                ],
            },
        )
    )
    assert result.outcome == "BLOCK"
    assert any(reason.code == "STALE_EVIDENCE" for reason in result.reasons)


def test_missing_assessment_blocks() -> None:
    result = evaluate_deployment_document(_base(risk={}))
    assert result.outcome == "BLOCK"
    assert any(reason.code == "MISSING_ASSESSMENT" for reason in result.reasons)


def test_granted_exception_allows_missing_evidence() -> None:
    result = evaluate_deployment_document(
        _base(
            asset={
                "risk_band": "HIGH",
                "data_classification": "INTERNAL",
                "autonomy_level": "HUMAN_IN_LOOP",
                "uses_customer_decision": False,
            },
            approvals={"security": True},
            risk={"band": "HIGH", "confidence": 0.9},
            evidence={
                "stale": False,
                "controls": [
                    {
                        "id": "CTRL-ML-PERF-001",
                        "type": "EVALUATION_RUN",
                        "required": True,
                        "status": "UNKNOWN",
                    }
                ],
            },
            exceptions=[
                {
                    "violation_code": "MISSING_REQUIRED_EVIDENCE",
                    "status": "GRANTED",
                    "expired": False,
                }
            ],
        )
    )
    assert result.outcome == "ALLOW"


def test_hash_failure_cannot_be_waived() -> None:
    result = evaluate_deployment_document(
        _base(
            asset={
                "risk_band": "HIGH",
                "data_classification": "INTERNAL",
                "autonomy_level": "HUMAN_IN_LOOP",
                "uses_customer_decision": False,
            },
            approvals={"security": True},
            risk={"band": "HIGH", "confidence": 0.9},
            evidence={
                "stale": False,
                "controls": [
                    {
                        "id": "CTRL-ML-PERF-001",
                        "type": "EVALUATION_RUN",
                        "required": True,
                        "status": "FAIL",
                    }
                ],
            },
            exceptions=[
                {
                    "violation_code": "EVIDENCE_HASH_FAILURE",
                    "status": "GRANTED",
                    "expired": False,
                }
            ],
        )
    )
    assert result.outcome == "BLOCK"
    assert any(reason.code == "EVIDENCE_HASH_FAILURE" for reason in result.reasons)


def test_open_incident_blocks_and_cannot_be_waived() -> None:
    result = evaluate_deployment_document(
        _base(
            incidents=[{"id": "inc_1", "status": "OPEN", "severity": "CRITICAL"}],
            exceptions=[
                {
                    "violation_code": "RUNTIME_INCIDENT",
                    "status": "GRANTED",
                    "expired": False,
                }
            ],
        )
    )
    assert result.outcome == "BLOCK"
    assert any(reason.code == "RUNTIME_INCIDENT" for reason in result.reasons)


def test_resolved_incident_does_not_block() -> None:
    result = evaluate_deployment_document(
        _base(incidents=[{"id": "inc_1", "status": "RESOLVED", "severity": "CRITICAL"}])
    )
    assert result.outcome == "ALLOW"


def _action_base(**overrides):
    document = {
        "asset": {
            "system_type": "AGENT",
            "status": "APPROVED",
            "deploy_authorized": True,
            "autonomy_level": "SEMI_AUTONOMOUS",
            "version_id": "ver_1",
        },
        "incidents": [],
        "request": {"action": "payments.refund", "resource": "account:retail-123", "amount": 50},
        "capability": {
            "action": "payments.refund",
            "resource_pattern": "account:retail-*",
            "resource_match": True,
            "max_amount": 500,
            "requires_approval": True,
            "approved": True,
        },
    }
    document.update(overrides)
    return document


def test_approved_capability_allows_in_pattern_refund() -> None:
    result = evaluate_action_document(_action_base())
    assert result.outcome == "ALLOW"
    assert result.reasons == []


def test_undeclared_and_resource_mismatch_deny() -> None:
    undeclared = evaluate_action_document(_action_base(capability=None))
    assert undeclared.outcome == "DENY"
    assert any(reason.code == "UNDECLARED_ACTION" for reason in undeclared.reasons)
    mismatch = evaluate_action_document(
        _action_base(
            request={"action": "payments.refund", "resource": "account:wholesale-1", "amount": 50},
            capability={
                "action": "payments.refund",
                "resource_match": False,
                "max_amount": 500,
                "requires_approval": True,
                "approved": True,
            },
        )
    )
    assert mismatch.outcome == "DENY"
    assert any(reason.code == "RESOURCE_NOT_PERMITTED" for reason in mismatch.reasons)


def test_amount_and_missing_approval_and_incident_deny() -> None:
    amount = evaluate_action_document(
        _action_base(
            request={"action": "payments.refund", "resource": "account:retail-123", "amount": 900}
        )
    )
    assert any(reason.code == "AMOUNT_EXCEEDS_LIMIT" for reason in amount.reasons)
    unapproved = evaluate_action_document(
        _action_base(
            capability={
                "action": "payments.refund",
                "resource_match": True,
                "max_amount": 500,
                "requires_approval": True,
                "approved": False,
            }
        )
    )
    assert any(reason.code == "MISSING_ACTION_APPROVAL" for reason in unapproved.reasons)
    incident = evaluate_action_document(
        _action_base(incidents=[{"id": "inc_1", "status": "OPEN", "severity": "CRITICAL"}])
    )
    assert incident.outcome == "DENY"
    assert any(reason.code == "RUNTIME_INCIDENT" for reason in incident.reasons)

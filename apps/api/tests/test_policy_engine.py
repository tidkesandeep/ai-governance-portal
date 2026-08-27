from aigov.domains.policy.engine import evaluate_deployment_document


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

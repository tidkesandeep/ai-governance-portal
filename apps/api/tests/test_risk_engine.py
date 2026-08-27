from aigov.domains.risk.engine import assess, band_for


def test_internal_analytics_is_low_or_medium() -> None:
    result = assess(
        {
            "name": "Cohort rollup",
            "systemType": "PREDICTIVE_MODEL",
            "businessPurpose": "Internal weekly reporting",
            "owner": "analytics",
            "environment": "dev",
            "dataClassification": "INTERNAL",
            "geography": "US",
            "autonomyLevel": "HUMAN_IN_LOOP",
            "customerImpact": "LOW",
            "financialImpact": "NONE",
            "usesCustomerDecision": False,
            "evaluationRefs": ["eval_internal"],
            "monitoringEnabled": True,
            "humanOversight": ["analyst_review"],
        }
    )
    assert result.risk_band in {"LOW", "MEDIUM"}
    assert result.confidence >= 0.85
    assert result.engine_version.startswith("risk-engine@")
    assert result.drivers[0].contribution >= 0


def test_fraud_model_is_high() -> None:
    result = assess(
        {
            "name": "Fraud Risk Model v4.2",
            "systemType": "PREDICTIVE_MODEL",
            "businessPurpose": "Score payment transactions for fraud",
            "owner": "payments-ml",
            "environment": "production",
            "dataClassification": "PII",
            "geography": "EU",
            "autonomyLevel": "ASSISTIVE",
            "customerImpact": "HIGH",
            "financialImpact": "HIGH",
            "usesCustomerDecision": True,
            "monitoringEnabled": False,
        }
    )
    assert result.score >= 60
    assert result.risk_band in {"HIGH", "CRITICAL"}
    codes = {driver.code for driver in result.drivers}
    assert "DATA_SENSITIVE" in codes
    assert "FINANCIAL_IMPACT" in codes


def test_autonomous_agent_has_hard_constraint() -> None:
    result = assess(
        {
            "name": "Dispute Resolution Agent",
            "systemType": "AGENT",
            "businessPurpose": "Resolve card disputes",
            "owner": "ops",
            "environment": "production",
            "dataClassification": "PII",
            "geography": "IN",
            "autonomyLevel": "AUTONOMOUS",
            "customerImpact": "HIGH",
            "financialImpact": "HIGH",
            "usesCustomerDecision": True,
        }
    )
    assert "PRIVILEGED_AUTONOMOUS_ACTION" in result.hard_constraints
    assert result.risk_band in {"HIGH", "CRITICAL"}


def test_bands() -> None:
    assert band_for(10) == "LOW"
    assert band_for(30) == "MEDIUM"
    assert band_for(60) == "HIGH"
    assert band_for(80) == "CRITICAL"

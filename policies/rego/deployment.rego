package aigov.deployment

# Slice-1 production deployment gate.
# Input document is assembled by the control plane; this bundle only decides.

default outcome := "ALLOW"

violation[{"code": "MISSING_SECURITY_APPROVAL", "severity": "HIGH", "message": "security approval required for HIGH or CRITICAL risk AI systems"}] {
	high_risk
	not input.approvals.security
}

violation[{"code": "MISSING_PRIVACY_APPROVAL", "severity": "HIGH", "message": "privacy approval required for PII or PCI processing"}] {
	sensitive_data
	not input.approvals.privacy
}

violation[{"code": "MISSING_HUMAN_OVERSIGHT", "severity": "HIGH", "message": "autonomous systems require human oversight controls"}] {
	input.asset.autonomy_level == "AUTONOMOUS"
	count(object.get(input.human_oversight, "controls", [])) == 0
}

violation[{"code": "MISSING_RISK_APPROVAL", "severity": "HIGH", "message": "risk approval required for HIGH or CRITICAL customer-decision systems"}] {
	high_risk
	input.asset.uses_customer_decision == true
	not input.approvals.risk
}

violation[{"code": "STALE_EVIDENCE", "severity": "MEDIUM", "message": "evidence is stale relative to the control freshness policy"}] {
	input.evidence.stale == true
}

violation[{"code": "LOW_CONFIDENCE", "severity": "MEDIUM", "message": "risk confidence is below the automated-gate threshold"}] {
	input.risk.confidence < 0.7
}

violation[{"code": "MISSING_ASSESSMENT", "severity": "HIGH", "message": "deployment gate requires a current risk assessment"}] {
	not input.risk.band
}

high_risk {
	input.asset.risk_band == "HIGH"
}

high_risk {
	input.asset.risk_band == "CRITICAL"
}

sensitive_data {
	input.asset.data_classification == "PII"
}

sensitive_data {
	input.asset.data_classification == "PCI"
}

sensitive_data {
	input.asset.data_classification == "RESTRICTED"
}

has_high_violation {
	violation[v]
	v.severity == "HIGH"
}

has_medium_violation {
	violation[v]
	v.severity == "MEDIUM"
}

outcome := "BLOCK" {
	has_high_violation
}

outcome := "REVIEW" {
	not has_high_violation
	has_medium_violation
}

allow {
	outcome == "ALLOW"
}

required_actions[action] {
	violation[v]
	action := actions[v.code]
}

actions := {
	"MISSING_SECURITY_APPROVAL": "complete security review",
	"MISSING_PRIVACY_APPROVAL": "complete privacy review",
	"MISSING_HUMAN_OVERSIGHT": "attach human oversight controls",
	"MISSING_RISK_APPROVAL": "complete risk review",
	"STALE_EVIDENCE": "refresh evaluation evidence",
	"LOW_CONFIDENCE": "supply missing risk attributes and reassess",
	"MISSING_ASSESSMENT": "run risk assessment",
}

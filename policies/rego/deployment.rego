package aigov.deployment

# Production deployment gate. Input is assembled by the control plane.

default outcome := "ALLOW"

violation[{"code": "MISSING_SECURITY_APPROVAL", "severity": "HIGH", "message": "security approval required for HIGH or CRITICAL risk AI systems"}] {
	high_risk
	not input.approvals.security
	not waived("MISSING_SECURITY_APPROVAL")
}

violation[{"code": "MISSING_PRIVACY_APPROVAL", "severity": "HIGH", "message": "privacy approval required for PII or PCI processing"}] {
	sensitive_data
	not input.approvals.privacy
	not waived("MISSING_PRIVACY_APPROVAL")
}

violation[{"code": "MISSING_HUMAN_OVERSIGHT", "severity": "HIGH", "message": "autonomous systems require human oversight controls"}] {
	input.asset.autonomy_level == "AUTONOMOUS"
	count(object.get(input.human_oversight, "controls", [])) == 0
	not waived("MISSING_HUMAN_OVERSIGHT")
}

violation[{"code": "MISSING_RISK_APPROVAL", "severity": "HIGH", "message": "risk approval required for HIGH or CRITICAL customer-decision systems"}] {
	high_risk
	input.asset.uses_customer_decision == true
	not input.approvals.risk
	not waived("MISSING_RISK_APPROVAL")
}

violation[{"code": "MISSING_REQUIRED_EVIDENCE", "severity": "HIGH", "message": "unknown evidence cannot satisfy a mandatory control"}] {
	control := input.evidence.controls[_]
	control.required == true
	control.status == "UNKNOWN"
	not waived("MISSING_REQUIRED_EVIDENCE")
}

violation[{"code": "EVIDENCE_HASH_FAILURE", "severity": "HIGH", "message": "evidence hash verification failed"}] {
	control := input.evidence.controls[_]
	control.required == true
	control.status == "FAIL"
}

violation[{"code": "STALE_EVIDENCE", "severity": "HIGH", "message": "stale evidence cannot satisfy a HIGH or CRITICAL control"}] {
	high_risk
	stale_required
	not waived("STALE_EVIDENCE")
}

violation[{"code": "STALE_EVIDENCE", "severity": "MEDIUM", "message": "evidence is stale relative to the control freshness policy"}] {
	not high_risk
	input.evidence.stale == true
	not waived("STALE_EVIDENCE")
}

violation[{"code": "LOW_CONFIDENCE", "severity": "MEDIUM", "message": "risk confidence is below the automated-gate threshold"}] {
	input.risk.confidence < 0.7
	not waived("LOW_CONFIDENCE")
}

violation[{"code": "MISSING_ASSESSMENT", "severity": "HIGH", "message": "deployment gate requires a current risk assessment"}] {
	not input.risk.band
}

violation[{"code": "RUNTIME_INCIDENT", "severity": "HIGH", "message": "an open runtime incident revokes deployment authorization"}] {
	incident := input.incidents[_]
	incident.status == "OPEN"
}

violation[{"code": "RUNTIME_DRIFT", "severity": "HIGH", "message": "observed runtime state does not match the authorized desired state"}] {
	input.reconciliation.high_drift == true
}

violation[{"code": "RUNTIME_DRIFT", "severity": "HIGH", "message": "observed runtime state does not match the authorized desired state"}] {
	input.reconciliation.status == "DRIFT"
	reason := input.reconciliation.reasons[_]
	reason.severity == "HIGH"
}

violation[{"code": "STALE_OBSERVATION", "severity": "HIGH", "message": "runtime observation is stale relative to the freshness window"}] {
	high_risk
	stale_observation
	not waived("STALE_OBSERVATION")
}

violation[{"code": "STALE_OBSERVATION", "severity": "MEDIUM", "message": "runtime observation is stale relative to the freshness window"}] {
	not high_risk
	stale_observation
	not waived("STALE_OBSERVATION")
}

stale_required {
	control := input.evidence.controls[_]
	control.required == true
	control.status == "STALE"
}

stale_required {
	input.evidence.stale == true
}

stale_observation {
	reason := input.reconciliation.reasons[_]
	reason.code == "STALE_OBSERVATION"
}

non_waivable := {
	"EVIDENCE_HASH_FAILURE": true,
	"MISSING_ASSESSMENT": true,
	"POLICY_ENGINE_UNAVAILABLE": true,
	"RUNTIME_INCIDENT": true,
	"RUNTIME_DRIFT": true,
}

waived(code) {
	not non_waivable[code]
	exc := input.exceptions[_]
	exc.violation_code == code
	exc.status == "GRANTED"
	exc.expired == false
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
	"MISSING_REQUIRED_EVIDENCE": "attach required evidence for the current asset version",
	"EVIDENCE_HASH_FAILURE": "re-upload evidence; stored digest does not match bytes",
	"RUNTIME_INCIDENT": "resolve the open incident and re-evaluate the deployment gate",
	"RUNTIME_DRIFT": "restore the authorized runtime version and re-evaluate the deployment gate",
	"STALE_OBSERVATION": "refresh the runtime observation within the freshness window",
}

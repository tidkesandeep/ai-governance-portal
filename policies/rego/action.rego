package aigov.action

# Agent action/resource gate. Input is assembled by the control plane.

default outcome := "ALLOW"

violation[{"code": "NOT_AN_AGENT", "severity": "HIGH", "message": "only AGENT systems may request action authorization"}] {
	input.asset.system_type != "AGENT"
}

violation[{"code": "NOT_DEPLOY_AUTHORIZED", "severity": "HIGH", "message": "the agent is not currently authorized to operate"}] {
	not input.asset.deploy_authorized
}

violation[{"code": "SYSTEM_BLOCKED", "severity": "HIGH", "message": "a blocked system cannot act"}] {
	input.asset.status == "BLOCKED"
}

violation[{"code": "RUNTIME_INCIDENT", "severity": "HIGH", "message": "an open runtime incident revokes action authorization"}] {
	incident := input.incidents[_]
	incident.status == "OPEN"
}

violation[{"code": "UNDECLARED_ACTION", "severity": "HIGH", "message": "the requested action is not declared for the current asset version"}] {
	input.capability == null
}

violation[{"code": "RESOURCE_NOT_PERMITTED", "severity": "HIGH", "message": "the requested resource is outside the declared capability pattern"}] {
	input.capability != null
	input.capability.resource_match != true
}

violation[{"code": "AMOUNT_EXCEEDS_LIMIT", "severity": "HIGH", "message": "the requested amount exceeds the capability ceiling"}] {
	input.capability != null
	input.capability.max_amount != null
	input.request.amount != null
	input.request.amount > input.capability.max_amount
}

violation[{"code": "MISSING_ACTION_APPROVAL", "severity": "HIGH", "message": "privileged or approval-gated capabilities require a reviewer grant"}] {
	input.capability != null
	input.capability.requires_approval == true
	not input.capability.approved
}

has_high_violation {
	violation[v]
	v.severity == "HIGH"
}

outcome := "DENY" {
	has_high_violation
}

allow {
	outcome == "ALLOW"
}

required_actions[action] {
	violation[v]
	action := actions[v.code]
}

actions := {
	"NOT_AN_AGENT": "register an AGENT system before requesting action authorization",
	"NOT_DEPLOY_AUTHORIZED": "evaluate the deployment gate to ALLOW before the agent may act",
	"SYSTEM_BLOCKED": "clear the blocked lifecycle and re-evaluate the deployment gate",
	"RUNTIME_INCIDENT": "resolve the open incident and re-authorize the action",
	"UNDECLARED_ACTION": "declare a version-bound capability for this action",
	"RESOURCE_NOT_PERMITTED": "declare a capability whose resource pattern covers this resource",
	"AMOUNT_EXCEEDS_LIMIT": "request a lower amount or raise the capability ceiling",
	"MISSING_ACTION_APPROVAL": "have a reviewer approve the capability",
	"POLICY_ENGINE_UNAVAILABLE": "restore the policy engine and retry action authorization",
}

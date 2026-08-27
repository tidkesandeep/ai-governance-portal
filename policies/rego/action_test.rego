package aigov.action

test_declared_refund_allows {
	result := outcome with input as {
		"asset": {
			"system_type": "AGENT",
			"status": "APPROVED",
			"deploy_authorized": true,
			"autonomy_level": "SEMI_AUTONOMOUS",
		},
		"incidents": [],
		"request": {"action": "payments.refund", "resource": "account:retail-123", "amount": 50},
		"capability": {
			"action": "payments.refund",
			"resource_pattern": "account:retail-*",
			"resource_match": true,
			"max_amount": 500,
			"requires_approval": true,
			"approved": true,
		},
	}
	result == "ALLOW"
}

test_undeclared_action_denies {
	result := outcome with input as {
		"asset": {
			"system_type": "AGENT",
			"status": "APPROVED",
			"deploy_authorized": true,
		},
		"incidents": [],
		"request": {"action": "ledger.write", "resource": "ledger:core"},
		"capability": null,
	}
	result == "DENY"
}

test_resource_mismatch_denies {
	result := outcome with input as {
		"asset": {
			"system_type": "AGENT",
			"status": "APPROVED",
			"deploy_authorized": true,
		},
		"incidents": [],
		"request": {"action": "payments.refund", "resource": "account:wholesale-1", "amount": 50},
		"capability": {
			"action": "payments.refund",
			"resource_pattern": "account:retail-*",
			"resource_match": false,
			"max_amount": 500,
			"requires_approval": true,
			"approved": true,
		},
	}
	result == "DENY"
}

test_open_incident_denies {
	result := outcome with input as {
		"asset": {
			"system_type": "AGENT",
			"status": "BLOCKED",
			"deploy_authorized": false,
		},
		"incidents": [{"id": "inc_1", "status": "OPEN", "severity": "CRITICAL"}],
		"request": {"action": "payments.refund", "resource": "account:retail-123", "amount": 50},
		"capability": {
			"action": "payments.refund",
			"resource_match": true,
			"requires_approval": true,
			"approved": true,
		},
	}
	result == "DENY"
}

test_missing_capability_approval_denies {
	result := outcome with input as {
		"asset": {
			"system_type": "AGENT",
			"status": "APPROVED",
			"deploy_authorized": true,
		},
		"incidents": [],
		"request": {"action": "payments.refund", "resource": "account:retail-123", "amount": 50},
		"capability": {
			"action": "payments.refund",
			"resource_match": true,
			"max_amount": 500,
			"requires_approval": true,
			"approved": false,
		},
	}
	result == "DENY"
}

package aigov.deployment

test_low_risk_internal_allows {
	result := outcome with input as {
		"asset": {
			"risk_band": "LOW",
			"data_classification": "INTERNAL",
			"autonomy_level": "HUMAN_IN_LOOP",
			"uses_customer_decision": false,
		},
		"approvals": {},
		"human_oversight": {"controls": []},
		"risk": {"band": "LOW", "confidence": 0.9},
		"evidence": {"stale": false},
	}
	result == "ALLOW"
}

test_high_risk_without_privacy_blocks {
	result := outcome with input as {
		"asset": {
			"risk_band": "HIGH",
			"data_classification": "PII",
			"autonomy_level": "ASSISTIVE",
			"uses_customer_decision": true,
		},
		"approvals": {"security": true},
		"human_oversight": {"controls": []},
		"risk": {"band": "HIGH", "confidence": 0.96},
		"evidence": {"stale": false},
	}
	result == "BLOCK"
}

test_stale_evidence_reviews {
	result := outcome with input as {
		"asset": {
			"risk_band": "LOW",
			"data_classification": "INTERNAL",
			"autonomy_level": "HUMAN_IN_LOOP",
			"uses_customer_decision": false,
		},
		"approvals": {},
		"human_oversight": {"controls": []},
		"risk": {"band": "LOW", "confidence": 0.9},
		"evidence": {"stale": true},
	}
	result == "REVIEW"
}

test_missing_required_evidence_blocks {
	result := outcome with input as {
		"asset": {
			"risk_band": "HIGH",
			"data_classification": "INTERNAL",
			"autonomy_level": "HUMAN_IN_LOOP",
			"uses_customer_decision": false,
		},
		"approvals": {"security": true},
		"human_oversight": {"controls": []},
		"risk": {"band": "HIGH", "confidence": 0.9},
		"evidence": {
			"stale": false,
			"controls": [{
				"id": "CTRL-ML-PERF-001",
				"required": true,
				"status": "UNKNOWN",
			}],
		},
	}
	result == "BLOCK"
}

test_autonomous_without_oversight_blocks {
	result := outcome with input as {
		"asset": {
			"risk_band": "MEDIUM",
			"data_classification": "INTERNAL",
			"autonomy_level": "AUTONOMOUS",
			"uses_customer_decision": false,
		},
		"approvals": {},
		"human_oversight": {"controls": []},
		"risk": {"band": "MEDIUM", "confidence": 0.9},
		"evidence": {"stale": false},
	}
	result == "BLOCK"
}

test_granted_exception_allows_missing_evidence {
	result := outcome with input as {
		"asset": {
			"risk_band": "HIGH",
			"data_classification": "INTERNAL",
			"autonomy_level": "HUMAN_IN_LOOP",
			"uses_customer_decision": false,
		},
		"approvals": {"security": true},
		"human_oversight": {"controls": []},
		"risk": {"band": "HIGH", "confidence": 0.9},
		"evidence": {
			"stale": false,
			"controls": [{
				"id": "CTRL-ML-PERF-001",
				"required": true,
				"status": "UNKNOWN",
			}],
		},
		"exceptions": [{
			"violation_code": "MISSING_REQUIRED_EVIDENCE",
			"status": "GRANTED",
			"expired": false,
		}],
	}
	result == "ALLOW"
}

test_hash_failure_exception_is_ignored {
	result := outcome with input as {
		"asset": {
			"risk_band": "HIGH",
			"data_classification": "INTERNAL",
			"autonomy_level": "HUMAN_IN_LOOP",
			"uses_customer_decision": false,
		},
		"approvals": {"security": true},
		"human_oversight": {"controls": []},
		"risk": {"band": "HIGH", "confidence": 0.9},
		"evidence": {
			"stale": false,
			"controls": [{
				"id": "CTRL-ML-PERF-001",
				"required": true,
				"status": "FAIL",
			}],
		},
		"exceptions": [{
			"violation_code": "EVIDENCE_HASH_FAILURE",
			"status": "GRANTED",
			"expired": false,
		}],
	}
	result == "BLOCK"
}

test_open_incident_blocks {
	result := outcome with input as {
		"asset": {
			"risk_band": "LOW",
			"data_classification": "INTERNAL",
			"autonomy_level": "HUMAN_IN_LOOP",
			"uses_customer_decision": false,
		},
		"approvals": {},
		"human_oversight": {"controls": []},
		"risk": {"band": "LOW", "confidence": 0.9},
		"evidence": {"stale": false},
		"incidents": [{"id": "inc_1", "status": "OPEN", "severity": "CRITICAL"}],
		"exceptions": [{
			"violation_code": "RUNTIME_INCIDENT",
			"status": "GRANTED",
			"expired": false,
		}],
	}
	result == "BLOCK"
}

test_high_drift_blocks_even_when_waived {
	result := outcome with input as {
		"asset": {
			"risk_band": "LOW",
			"data_classification": "INTERNAL",
			"autonomy_level": "HUMAN_IN_LOOP",
			"uses_customer_decision": false,
		},
		"approvals": {},
		"human_oversight": {"controls": []},
		"risk": {"band": "LOW", "confidence": 0.9},
		"evidence": {"stale": false},
		"reconciliation": {
			"status": "DRIFT",
			"high_drift": true,
			"reasons": [{"code": "ASSET_VERSION_MISMATCH", "severity": "HIGH"}],
		},
		"exceptions": [{
			"violation_code": "RUNTIME_DRIFT",
			"status": "GRANTED",
			"expired": false,
		}],
	}
	result == "BLOCK"
}

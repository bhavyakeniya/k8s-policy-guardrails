package policies.privilege_escalation

test_allow_privilege_escalation_true_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {"containers": [{"name": "app", "securityContext": {"allowPrivilegeEscalation": true}}]},
	}
	count(deny) > 0 with input as mock_input
}

test_allow_privilege_escalation_missing_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {"containers": [{"name": "app", "securityContext": {}}]},
	}
	count(deny) > 0 with input as mock_input
}

test_allow_privilege_escalation_false_allowed if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "good-pod"},
		"spec": {"containers": [{"name": "app", "securityContext": {"allowPrivilegeEscalation": false}}]},
	}
	count(deny) == 0 with input as mock_input
}

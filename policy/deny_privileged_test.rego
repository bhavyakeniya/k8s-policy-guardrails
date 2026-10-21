package policies.privileged

test_privileged_container_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {"containers": [{"name": "app", "securityContext": {"privileged": true}}]},
	}
	count(deny) > 0 with input as mock_input
}

test_non_privileged_container_allowed if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "good-pod"},
		"spec": {"containers": [{"name": "app", "securityContext": {"privileged": false}}]},
	}
	count(deny) == 0 with input as mock_input
}

test_privileged_in_deployment_template_denied if {
	mock_input := {
		"kind": "Deployment",
		"metadata": {"name": "bad-deploy"},
		"spec": {"template": {"spec": {"containers": [{"name": "app", "securityContext": {"privileged": true}}]}}},
	}
	count(deny) > 0 with input as mock_input
}

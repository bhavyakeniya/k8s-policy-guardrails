package policies.non_root

test_root_container_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {"containers": [{"name": "app", "securityContext": {}}]},
	}
	count(deny) > 0 with input as mock_input
}

test_container_level_non_root_allowed if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "good-pod"},
		"spec": {"containers": [{"name": "app", "securityContext": {"runAsNonRoot": true}}]},
	}
	count(deny) == 0 with input as mock_input
}

test_pod_level_non_root_allowed if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "good-pod"},
		"spec": {
			"securityContext": {"runAsNonRoot": true},
			"containers": [{"name": "app"}],
		},
	}
	count(deny) == 0 with input as mock_input
}

test_container_override_to_root_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {
			"securityContext": {"runAsNonRoot": true},
			"containers": [{"name": "app", "securityContext": {"runAsNonRoot": false}}],
		},
	}
	count(deny) > 0 with input as mock_input
}

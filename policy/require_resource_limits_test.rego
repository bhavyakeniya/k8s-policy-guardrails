package policies.resource_limits

test_missing_limits_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {"containers": [{"name": "app"}]},
	}
	count(deny) == 2 with input as mock_input
}

test_missing_memory_limit_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {"containers": [{"name": "app", "resources": {"limits": {"cpu": "500m"}}}]},
	}
	count(deny) == 1 with input as mock_input
}

test_full_limits_allowed if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "good-pod"},
		"spec": {"containers": [{"name": "app", "resources": {"limits": {"cpu": "500m", "memory": "256Mi"}}}]},
	}
	count(deny) == 0 with input as mock_input
}

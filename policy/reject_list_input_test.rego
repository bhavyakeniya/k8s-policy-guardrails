package policies.reject_list_input

test_list_kind_denied if {
	mock_input := {"kind": "List", "items": [{"kind": "Pod", "metadata": {"name": "x"}, "spec": {"containers": [{"name": "app", "securityContext": {"privileged": true}}]}}]}
	count(deny) > 0 with input as mock_input
}

test_pod_kind_allowed if {
	mock_input := {"kind": "Pod", "metadata": {"name": "x"}, "spec": {"containers": [{"name": "app"}]}}
	count(deny) == 0 with input as mock_input
}

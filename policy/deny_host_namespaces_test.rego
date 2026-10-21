package policies.host_namespaces

test_host_network_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {"hostNetwork": true, "containers": [{"name": "app"}]},
	}
	count(deny) > 0 with input as mock_input
}

test_host_pid_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {"hostPID": true, "containers": [{"name": "app"}]},
	}
	count(deny) > 0 with input as mock_input
}

test_host_ipc_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {"hostIPC": true, "containers": [{"name": "app"}]},
	}
	count(deny) > 0 with input as mock_input
}

test_no_host_namespaces_allowed if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "good-pod"},
		"spec": {"containers": [{"name": "app"}]},
	}
	count(deny) == 0 with input as mock_input
}

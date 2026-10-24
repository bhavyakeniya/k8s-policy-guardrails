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

# Confirmed against Kubernetes' own docs: a Windows Pod with
# allowPrivilegeEscalation set at all - true, false, doesn't matter - is
# rejected outright by the real API server. This policy used to require
# setting it to false unconditionally, which made it and the API server
# mutually impossible to satisfy for a legitimate Windows workload.
test_windows_pod_without_allow_privilege_escalation_allowed if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "windows-pod"},
		"spec": {"os": {"name": "windows"}, "containers": [{"name": "app", "securityContext": {}}]},
	}
	count(deny) == 0 with input as mock_input
}

test_linux_pod_still_denied_when_unset if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "linux-pod"},
		"spec": {"os": {"name": "linux"}, "containers": [{"name": "app", "securityContext": {}}]},
	}
	count(deny) > 0 with input as mock_input
}

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

test_init_container_root_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {
			"containers": [{"name": "app", "securityContext": {"runAsNonRoot": true}}],
			"initContainers": [{"name": "init-app", "securityContext": {}}],
		},
	}
	count(deny) > 0 with input as mock_input
}

test_ephemeral_container_root_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {
			"containers": [{"name": "app", "securityContext": {"runAsNonRoot": true}}],
			"ephemeralContainers": [{"name": "debug", "securityContext": {}}],
		},
	}
	count(deny) > 0 with input as mock_input
}

# The exact contradiction confirmed as a real false negative before these
# rules existed: pod-level runAsNonRoot: true satisfied the boolean-flag
# check, but the same container explicitly sets runAsUser: 0 - which is
# root, regardless of what the flag claims. Passed kubeconform, passed a
# server-side dry-run, and passed every policy in this repo (12/12)
# before this fix.
test_explicit_root_uid_contradicts_run_as_non_root_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "contradiction-pod"},
		"spec": {
			"securityContext": {"runAsNonRoot": true},
			"containers": [{"name": "app", "securityContext": {"runAsUser": 0}}],
		},
	}
	count(deny) > 0 with input as mock_input
}

test_init_container_explicit_root_uid_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {
			"containers": [{"name": "app", "securityContext": {"runAsNonRoot": true}}],
			"initContainers": [{"name": "init-app", "securityContext": {"runAsNonRoot": true, "runAsUser": 0}}],
		},
	}
	count(deny) > 0 with input as mock_input
}

test_ephemeral_container_explicit_root_uid_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {
			"containers": [{"name": "app", "securityContext": {"runAsNonRoot": true}}],
			"ephemeralContainers": [{"name": "debug", "securityContext": {"runAsNonRoot": true, "runAsUser": 0}}],
		},
	}
	count(deny) > 0 with input as mock_input
}

test_pod_level_root_uid_inherited_by_container_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {
			"securityContext": {"runAsNonRoot": true, "runAsUser": 0},
			"containers": [{"name": "app"}],
		},
	}
	count(deny) > 0 with input as mock_input
}

# A container that overrides the pod-level root UID with a real non-zero
# UID must not be falsely denied just because the pod spec sets 0.
test_container_overrides_pod_level_root_uid_allowed if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "good-pod"},
		"spec": {
			"securityContext": {"runAsNonRoot": true, "runAsUser": 0},
			"containers": [{"name": "app", "securityContext": {"runAsNonRoot": true, "runAsUser": 1000}}],
		},
	}
	count(deny) == 0 with input as mock_input
}

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

# Confirmed as a real bypass before the quantity check existed:
# limits: {cpu: "0", memory: "0"} is a valid Kubernetes manifest (only
# negative quantities are rejected by validation) and passed every policy
# clean. Every zero representation below must still be denied.
test_zero_string_limits_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {"containers": [{"name": "app", "resources": {"limits": {"cpu": "0", "memory": "0"}}}]},
	}
	count(deny) == 2 with input as mock_input
}

test_zero_with_milli_suffix_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {"containers": [{"name": "app", "resources": {"limits": {"cpu": "0m", "memory": "256Mi"}}}]},
	}
	count(deny) == 1 with input as mock_input
}

test_zero_with_binary_suffix_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {"containers": [{"name": "app", "resources": {"limits": {"cpu": "500m", "memory": "0Mi"}}}]},
	}
	count(deny) == 1 with input as mock_input
}

test_zero_decimal_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {"containers": [{"name": "app", "resources": {"limits": {"cpu": "0.0", "memory": "256Mi"}}}]},
	}
	count(deny) == 1 with input as mock_input
}

# Unquoted YAML like `cpu: 0` parses as a JSON number, not the string "0" -
# the check has to handle both.
test_zero_as_unquoted_number_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {"containers": [{"name": "app", "resources": {"limits": {"cpu": 0, "memory": "256Mi"}}}]},
	}
	count(deny) == 1 with input as mock_input
}

# Confirmed as a real bypass before full-format validation existed: these
# three all passed when only the leading numeric prefix was checked.
# kubeconform does NOT catch these either - confirmed directly, it
# reports cpu: "1garbage" as schema-valid - so this check has to do it.
test_malformed_garbage_suffix_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {"containers": [{"name": "app", "resources": {"limits": {"cpu": "1garbage", "memory": "256Mi"}}}]},
	}
	count(deny) == 1 with input as mock_input
}

test_malformed_mib_suffix_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {"containers": [{"name": "app", "resources": {"limits": {"cpu": "500m", "memory": "1MiB"}}}]},
	}
	count(deny) == 1 with input as mock_input
}

test_malformed_bare_exponent_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {"containers": [{"name": "app", "resources": {"limits": {"cpu": "1e", "memory": "256Mi"}}}]},
	}
	count(deny) == 1 with input as mock_input
}

test_valid_exponent_notation_allowed if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "good-pod"},
		"spec": {"containers": [{"name": "app", "resources": {"limits": {"cpu": "1e3", "memory": "256Mi"}}}]},
	}
	count(deny) == 0 with input as mock_input
}

test_positive_unquoted_number_allowed if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "good-pod"},
		"spec": {"containers": [{"name": "app", "resources": {"limits": {"cpu": 2, "memory": "256Mi"}}}]},
	}
	count(deny) == 0 with input as mock_input
}

test_positive_decimal_with_binary_suffix_allowed if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "good-pod"},
		"spec": {"containers": [{"name": "app", "resources": {"limits": {"cpu": "0.5", "memory": ".5Gi"}}}]},
	}
	count(deny) == 0 with input as mock_input
}

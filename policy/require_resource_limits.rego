package policies.resource_limits

import data.common

# Resource limits are NOT a Kubernetes Pod Security Standards control -
# checked against the official PSS baseline/restricted profile lists rather
# than assumed, and they cover host namespaces, privileged, capabilities,
# non-root, privilege escalation, seccomp and volume types, not resource
# quotas. This aligns with the separate Kubernetes security checklist's
# resource-management guidance instead: every container must declare both
# CPU and memory limits, and those limits must be positive, so a bad
# deploy can't starve its node.
#
# A bare "the key exists" check is not enough - confirmed directly:
# limits: {cpu: "0", memory: "0"} passed this policy before the quantity
# check existed. Kubernetes' own validation only rejects NEGATIVE
# quantities, and the kubelet treats a zero limit as effectively
# unlimited, so "0" is a valid Kubernetes value that defeats the entire
# point of requiring a limit. A Kubernetes resource quantity can express
# zero in many forms ("0", "0m", "0Mi", "0.0", ".0Gi", a bare JSON number
# 0 if the YAML left it unquoted) - the fix parses the leading numeric
# magnitude out of any of those forms rather than special-casing one
# string literal.

deny contains msg if {
	container := common.resource_managed_containers[_]
	not has_positive_quantity(container, "cpu")
	msg := sprintf("%s/%s: container %q is missing resources.limits.cpu, or it is zero/non-positive", [input.kind, common.name, container.name])
}

deny contains msg if {
	container := common.resource_managed_containers[_]
	not has_positive_quantity(container, "memory")
	msg := sprintf("%s/%s: container %q is missing resources.limits.memory, or it is zero/non-positive", [input.kind, common.name, container.name])
}

has_positive_quantity(container, key) if {
	is_positive_quantity(container.resources.limits[key])
}

is_positive_quantity(value) if {
	is_number(value)
	value > 0
}

is_positive_quantity(value) if {
	is_string(value)
	matches := regex.find_all_string_submatch_n(`^([+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+))`, value, 1)
	count(matches) > 0
	num := to_number(matches[0][1])
	num > 0
}

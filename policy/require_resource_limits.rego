package policies.resource_limits

import data.common

# Resource limits are NOT a Kubernetes Pod Security Standards control -
# checked against the official PSS baseline/restricted profile lists rather
# than assumed, and they cover host namespaces, privileged, capabilities,
# non-root, privilege escalation, seccomp and volume types, not resource
# quotas. This aligns with the separate Kubernetes security checklist's
# resource-management guidance instead: every container must declare both
# CPU and memory limits, the value must be a well-formed Kubernetes
# quantity, and it must be positive, so a bad deploy can't starve its node.
#
# A bare "the key exists" check is not enough - confirmed directly:
# limits: {cpu: "0", memory: "0"} passed this policy before the quantity
# check existed. Kubernetes' own validation only rejects NEGATIVE
# quantities, and the kubelet treats a zero limit as effectively
# unlimited, so "0" is a valid Kubernetes value that defeats the entire
# point of requiring a limit.
#
# Format matters too, not just magnitude - confirmed directly: "1garbage",
# "1MiB" (not a real suffix - the real one is "Mi"), and "1e" (exponent
# notation needs digits after the e) all passed a first version of this
# check that only extracted the leading numeric prefix and ignored
# whatever followed it. kubeconform does NOT catch this class of mistake
# either - checked directly: it reports cpu: "1garbage" as valid, because
# the Kubernetes OpenAPI schema types resources.limits.cpu as a plain
# string with no format/pattern constraint; the real apiserver only
# rejects a malformed quantity string during semantic admission, a step
# schema validation doesn't perform. quantity_pattern below anchors the
# ENTIRE value against Kubernetes' actual quantity grammar (signed number,
# then an optional suffix from the specific binarySI/decimalSI/exponent
# set Kubernetes defines - not a free-form unit) rather than reimplementing
# full unit-conversion arithmetic, which this check deliberately does not
# attempt: it is validating shape and sign, not converting "0.5Gi" into
# bytes.

deny contains msg if {
	container := common.resource_managed_containers[_]
	not has_valid_positive_quantity(container, "cpu")
	msg := sprintf("%s/%s: container %q is missing resources.limits.cpu, or it is not a positive, well-formed Kubernetes quantity", [input.kind, common.name, container.name])
}

deny contains msg if {
	container := common.resource_managed_containers[_]
	not has_valid_positive_quantity(container, "memory")
	msg := sprintf("%s/%s: container %q is missing resources.limits.memory, or it is not a positive, well-formed Kubernetes quantity", [input.kind, common.name, container.name])
}

has_valid_positive_quantity(container, key) if {
	is_positive_quantity(container.resources.limits[key])
}

is_positive_quantity(value) if {
	is_number(value)
	value > 0
}

# Kubernetes' quantity suffixes: binarySI (Ki/Mi/Gi/Ti/Pi/Ei), decimalSI
# (n/u/m/k/M/G/T/P/E, or none), or a decimal exponent (e/E followed by a
# signed integer). Anchored start-to-end, not just a leading-prefix match.
quantity_pattern := `^[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(Ki|Mi|Gi|Ti|Pi|Ei|n|u|m|k|M|G|T|P|E|[eE][+-]?[0-9]+)?$`

is_positive_quantity(value) if {
	is_string(value)
	regex.match(quantity_pattern, value)
	matches := regex.find_all_string_submatch_n(`^([+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+))`, value, 1)
	num := to_number(matches[0][1])
	num > 0
}

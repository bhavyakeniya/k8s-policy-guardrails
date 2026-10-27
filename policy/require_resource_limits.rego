package policies.resource_limits

import data.common

# Resource limits are NOT a Kubernetes Pod Security Standards control -
# checked against the official PSS baseline/restricted profile lists
# rather than assumed; PSS covers host namespaces, privileged,
# capabilities, non-root, privilege escalation, seccomp and volume types,
# not resource quotas. This aligns with the separate Kubernetes security
# checklist's resource-management guidance instead.
#
# Scope: manifest hygiene, not resource governance. Requires a positive,
# syntactically valid CPU/memory limit on every container - nothing more.
# It does not reject an absurd single value (cpu: "1E" is just as valid
# syntactically as "1"), and no single-Pod policy can constrain aggregate
# consumption across replicas or a namespace, since that requires
# comparing against every other workload at once. Kubernetes' own
# mechanisms for those two problems are LimitRange (per-container/per-Pod
# ceilings) and ResourceQuota (namespace-wide aggregate ceilings) - see
# examples/reference/limitrange-resourcequota.yaml for illustrative,
# unenforced examples; a cluster admin applies these once per namespace,
# not as part of a workload manifest or this OPA policy set.
#
# A bare "the key exists" check is not enough: limits: {cpu: "0"} is a
# valid Kubernetes value (validation only rejects negative quantities,
# and the kubelet treats zero as effectively unlimited), which would
# defeat the entire point of requiring a limit. quantity_pattern below
# anchors the ENTIRE value against Kubernetes' actual quantity grammar
# (signed number, then an optional suffix from the specific
# binarySI/decimalSI/exponent set Kubernetes defines) rather than just
# extracting a leading numeric prefix, which would accept "1garbage" or
# "1MiB" (not a real suffix - the real one is "Mi"). This validates shape
# and sign, not full unit-conversion arithmetic (it never turns "0.5Gi"
# into a byte count) - deliberately scoped short of reimplementing
# Kubernetes' Quantity parser. kubeconform does not fill this gap either:
# it types resources.limits.cpu/memory as a plain OpenAPI string with no
# format constraint, so malformed quantities pass it too.
#
# Explicit scope boundary: this validates positive and syntactically
# well-formed, not full Kubernetes CPU semantics. cpu: "0.0005" is finer
# than Kubernetes' documented 1m/0.001 CPU precision floor and passes -
# Kubernetes' own handling of sub-milli precision is internal
# truncation/rounding in apimachinery, not a clearly-documented hard
# admission rejection this repo could reproduce with confidence, so
# CPU-specific precision enforcement isn't attempted on top of the
# general quantity grammar.
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

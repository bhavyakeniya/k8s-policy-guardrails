package policies.reject_list_input

# A kind: List wrapping other resources in its `items` array is a single
# opaque JSON/YAML document from conftest's point of view. Every other
# policy in this repo reads input.kind/input.spec/input.metadata directly,
# assuming input IS the resource - none of them look inside items[], so a
# privileged Pod wrapped in a List silently evaluates clean. Verified
# directly: a List containing a privileged, host-networked Pod passed
# 11/11 before this policy existed.
#
# Fixing this for real means rewriting every all_containers/all_pod_specs
# rule in common.rego, and every input.kind/input.metadata.name reference
# across every policy file, to operate over a documents[] set instead of
# input directly - a real but much larger refactor. Rejecting List inputs
# outright is the faster, safer fix: submit individual manifests (or
# multi-document --- separated YAML, which conftest already evaluates
# correctly per-document) instead of a List wrapper.

deny contains msg if {
	input.kind == "List"
	msg := "kind: List is rejected outright - none of this repo's policies inspect items[], so a violation inside a List silently passes. Submit individual manifests, or multi-document YAML (---  separated), instead."
}

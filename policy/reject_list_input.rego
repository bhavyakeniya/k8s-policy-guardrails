package policies.reject_list_input

# A kind: List wrapping other resources in its `items` array is a single
# opaque JSON/YAML document from conftest's point of view. Every other
# policy in this repo reads input.kind/input.spec/input.metadata directly,
# assuming input IS the resource - none of them look inside items[], so a
# privileged Pod wrapped in a List silently evaluates clean. Verified
# directly: a List containing a privileged, host-networked Pod passed
# 11/11 before this policy existed.
#
# Kubernetes doesn't only use the bare "List" kind for collections - the
# API has dozens of resource-specific collection kinds (PodList,
# DeploymentList, ServiceList, ...). Checking only input.kind == "List"
# missed every one of them: confirmed directly, a privileged, host-
# networked Pod wrapped in kind: PodList also passed 11/11. Checking
# endswith(input.kind, "List") AND an items array catches the general
# shape without also matching some unrelated resource whose kind
# coincidentally ends in "List" but isn't actually a collection.
#
# Fixing this for real means rewriting every security_relevant_containers/
# resource_managed_containers/all_pod_specs rule in common.rego, and every
# input.kind/input.metadata.name reference across every policy file, to
# operate over a documents[] set instead of input directly - a real but
# much larger refactor. Rejecting List-shaped inputs outright is the
# faster, safer fix: submit individual manifests (or multi-document ---
# separated YAML, which conftest already evaluates correctly per
# document) instead of a List wrapper.

deny contains msg if {
	endswith(input.kind, "List")
	input.items
	msg := sprintf("kind: %s is a collection and is rejected outright - none of this repo's policies inspect items[], so a violation inside one silently passes. Submit individual manifests, or multi-document YAML (---  separated), instead.", [input.kind])
}

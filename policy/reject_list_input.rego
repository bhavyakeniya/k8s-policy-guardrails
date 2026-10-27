package policies.reject_list_input

# Every policy in this repo reads input.kind/input.spec/input.metadata
# directly, assuming input IS the resource - none of them look inside
# items[], so a violation inside a List (or a resource-specific
# collection kind like PodList/DeploymentList - Kubernetes uses dozens of
# these, not just the bare "List") silently evaluates clean. Checking
# endswith(input.kind, "List") AND an items array catches the general
# shape without matching an unrelated resource whose kind coincidentally
# ends in "List".
#
# Properly supporting collections means rewriting every helper in
# common.rego and every input.kind/input.metadata.name reference across
# every policy to operate over a documents[] set instead of input
# directly - a real but much larger refactor. Rejecting the input
# outright is the safer near-term fix: submit individual manifests, or
# multi-document YAML (--- separated), which conftest already evaluates
# correctly per document.
deny contains msg if {
	endswith(input.kind, "List")
	input.items
	msg := sprintf("kind: %s is a collection and is rejected outright - none of this repo's policies inspect items[], so a violation inside one silently passes. Submit individual manifests, or multi-document YAML (---  separated), instead.", [input.kind])
}

package policies.resource_limits

import data.common

# Aligned with the Kubernetes Pod Security Standards / resource-quota
# guidance rather than a single CIS control: every container must declare
# both CPU and memory limits so a bad deploy can't starve its node.

deny contains msg if {
	container := common.all_containers[_]
	not container.resources.limits.cpu
	msg := sprintf("%s/%s: container %q is missing resources.limits.cpu", [input.kind, common.name, container.name])
}

deny contains msg if {
	container := common.all_containers[_]
	not container.resources.limits.memory
	msg := sprintf("%s/%s: container %q is missing resources.limits.memory", [input.kind, common.name, container.name])
}

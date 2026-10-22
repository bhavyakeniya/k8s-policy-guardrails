package policies.resource_limits

import data.common

# Resource limits are NOT a Kubernetes Pod Security Standards control -
# checked against the official PSS baseline/restricted profile lists rather
# than assumed, and they cover host namespaces, privileged, capabilities,
# non-root, privilege escalation, seccomp and volume types, not resource
# quotas. This aligns with the separate Kubernetes security checklist's
# resource-management guidance instead: every container must declare both
# CPU and memory limits so a bad deploy can't starve its node.

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

package policies.privilege_escalation

import data.common

# CIS Kubernetes Benchmark 5.2.5 - Minimize the admission of containers with
# allowPrivilegeEscalation

deny contains msg if {
	container := common.all_containers[_]
	not container.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("%s/%s: container %q must explicitly set allowPrivilegeEscalation: false", [input.kind, common.name, container.name])
}

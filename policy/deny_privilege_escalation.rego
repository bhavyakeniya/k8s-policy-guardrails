package policies.privilege_escalation

import data.common

# CIS Kubernetes Benchmark, Pod Security Policies section ("minimize the
# admission of containers with allowPrivilegeEscalation") - see
# deny_privileged.rego for why no specific control number is cited.

deny contains msg if {
	container := common.all_containers[_]
	not container.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("%s/%s: container %q must explicitly set allowPrivilegeEscalation: false", [input.kind, common.name, container.name])
}

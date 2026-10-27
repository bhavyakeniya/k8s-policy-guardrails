package policies.privilege_escalation

import data.common

# CIS Kubernetes Benchmark, Pod Security Policies section ("minimize the
# admission of containers with allowPrivilegeEscalation") - see
# deny_privileged.rego for why no specific control number is cited.
#
# Linux-only control, skipped for Windows pods: the API server rejects a
# Windows Pod outright if allowPrivilegeEscalation is set at all, so
# requiring it would make this policy and the real API server mutually
# impossible to satisfy for a legitimate Windows workload.

deny contains msg if {
	not common.is_windows_pod
	container := common.security_relevant_containers[_]
	not container.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("%s/%s: container %q must explicitly set allowPrivilegeEscalation: false", [input.kind, common.name, container.name])
}

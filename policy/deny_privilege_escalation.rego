package policies.privilege_escalation

import data.common

# CIS Kubernetes Benchmark, Pod Security Policies section ("minimize the
# admission of containers with allowPrivilegeEscalation") - see
# deny_privileged.rego for why no specific control number is cited.
#
# Linux-only control, skipped entirely for Windows pods - confirmed
# against Kubernetes' own Pod Security Standards docs: a Windows Pod is
# rejected by the API server outright if allowPrivilegeEscalation is set
# at all, so requiring it to be set to false for every container would
# make this policy and the real API server mutually impossible to
# satisfy for a legitimate Windows workload.

deny contains msg if {
	not common.is_windows_pod
	container := common.security_relevant_containers[_]
	not container.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("%s/%s: container %q must explicitly set allowPrivilegeEscalation: false", [input.kind, common.name, container.name])
}

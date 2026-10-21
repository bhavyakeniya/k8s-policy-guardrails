package policies.privileged

import data.common

# CIS Kubernetes Benchmark 5.2.1 - Minimize the admission of privileged containers

deny contains msg if {
	container := common.all_containers[_]
	container.securityContext.privileged == true
	msg := sprintf("%s/%s: container %q must not run privileged", [input.kind, common.name, container.name])
}

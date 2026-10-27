package policies.privileged

import data.common

# CIS Kubernetes Benchmark, Pod Security Policies section ("minimize the
# admission of privileged containers") - control numbering has shifted
# across benchmark versions, so no specific X.Y.Z number is cited here;
# verify against whichever benchmark version your org has adopted.

deny contains msg if {
	container := common.security_relevant_containers[_]
	container.securityContext.privileged == true
	msg := sprintf("%s/%s: container %q must not run privileged", [input.kind, common.name, container.name])
}

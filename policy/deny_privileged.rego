package policies.privileged

import data.common

# CIS Kubernetes Benchmark, Pod Security Policies section ("minimize the
# admission of privileged containers") - control numbering has shifted
# across benchmark versions in ways that contradicted each other across
# multiple sources I checked, so a specific X.Y.Z number isn't cited here;
# verify against whichever benchmark version your org has actually adopted.

deny contains msg if {
	container := common.security_relevant_containers[_]
	container.securityContext.privileged == true
	msg := sprintf("%s/%s: container %q must not run privileged", [input.kind, common.name, container.name])
}

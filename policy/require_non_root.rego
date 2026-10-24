package policies.non_root

import data.common

# CIS Kubernetes Benchmark, Pod Security Policies section ("minimize the
# admission of root containers") - see deny_privileged.rego for why no
# specific control number is cited.
# Pod-level runAsNonRoot satisfies this for every container (including init
# and ephemeral containers) that doesn't override it, so a container only
# fails when neither it nor the pod spec sets runAsNonRoot: true.

deny contains msg if {
	container := common.security_relevant_containers[_]
	not container_is_non_root(container)
	msg := sprintf("%s/%s: container %q must run as non-root (set runAsNonRoot: true)", [input.kind, common.name, container.name])
}

container_is_non_root(container) if {
	container.securityContext.runAsNonRoot == true
}

container_is_non_root(container) if {
	not container.securityContext.runAsNonRoot == false
	common.pod_runs_as_non_root
}

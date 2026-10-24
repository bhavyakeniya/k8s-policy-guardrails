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

# runAsNonRoot is a boolean flag; it was never cross-checked against an
# explicit UID actually contradicting it. Confirmed directly: a Pod with
# pod-level runAsNonRoot: true AND a container explicitly setting
# runAsUser: 0 passed every policy in this repo clean - kubeconform
# accepts it, a server-side dry-run accepts it (the kubelet would
# ultimately refuse to start the container, so this isn't a runtime
# privilege bypass, but it is a real CI false negative for a policy
# literally named "require non-root"), and Kubernetes' Restricted PSS
# separately prohibits runAsUser: 0 regardless of runAsNonRoot. Checked at
# both levels, covering regular/init/ephemeral containers via the same
# security_relevant_containers set everything else here uses.
deny contains msg if {
	container := common.security_relevant_containers[_]
	container.securityContext.runAsUser == 0
	msg := sprintf("%s/%s: container %q sets runAsUser: 0, which is root regardless of runAsNonRoot", [input.kind, common.name, container.name])
}

deny contains msg if {
	container := common.security_relevant_containers[_]
	not container.securityContext.runAsUser
	common.pod_run_as_user_is_zero
	msg := sprintf("%s/%s: container %q inherits runAsUser: 0 from the pod spec, which is root regardless of runAsNonRoot", [input.kind, common.name, container.name])
}

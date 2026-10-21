package policies.non_root

import data.common

# CIS Kubernetes Benchmark 5.2.6 - Minimize the admission of root containers
# Pod-level runAsNonRoot satisfies this for every container that doesn't
# override it, so a container only fails when neither it nor its pod spec
# sets runAsNonRoot: true.

deny contains msg if {
	spec := common.all_pod_specs[_]
	container := spec.containers[_]
	not pod_or_container_is_non_root(spec, container)
	msg := sprintf("%s/%s: container %q must run as non-root (set runAsNonRoot: true)", [input.kind, common.name, container.name])
}

pod_or_container_is_non_root(_, container) if {
	container.securityContext.runAsNonRoot == true
}

pod_or_container_is_non_root(spec, container) if {
	not container.securityContext.runAsNonRoot == false
	spec.securityContext.runAsNonRoot == true
}

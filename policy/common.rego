package common

# Shared helpers used by every policy package in this repo.
# Flattens the places a container can appear across the manifest kinds
# this repo checks (Pod, and Pod-template-shaped kinds like Deployment,
# StatefulSet, DaemonSet, Job, CronJob's jobTemplate).

name := input.metadata.name

all_containers contains c if {
	c := input.spec.containers[_]
}

all_containers contains c if {
	c := input.spec.initContainers[_]
}

all_containers contains c if {
	c := input.spec.template.spec.containers[_]
}

all_containers contains c if {
	c := input.spec.template.spec.initContainers[_]
}

all_containers contains c if {
	c := input.spec.jobTemplate.spec.template.spec.containers[_]
}

all_containers contains c if {
	c := input.spec.ephemeralContainers[_]
}

all_containers contains c if {
	c := input.spec.template.spec.ephemeralContainers[_]
}

# True when any pod-shaped spec on this manifest sets runAsNonRoot at the
# pod level. Safe to check across all shapes at once: a real manifest only
# ever populates one of Pod/.template.spec/.jobTemplate.spec.template.spec.
pod_runs_as_non_root if {
	some s in all_pod_specs
	s.securityContext.runAsNonRoot == true
}

all_pod_specs contains s if {
	s := input.spec
	is_pod_shaped(s)
}

all_pod_specs contains s if {
	s := input.spec.template.spec
	is_pod_shaped(s)
}

all_pod_specs contains s if {
	s := input.spec.jobTemplate.spec.template.spec
	is_pod_shaped(s)
}

is_pod_shaped(s) if {
	s.containers
}

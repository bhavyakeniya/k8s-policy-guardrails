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

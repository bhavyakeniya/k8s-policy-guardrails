package common

# Shared helpers used by every policy package in this repo.
# Flattens the places a container can appear across the manifest kinds
# this repo checks (Pod, and Pod-template-shaped kinds like Deployment,
# StatefulSet, DaemonSet, Job, CronJob's jobTemplate).

# Falls back through name -> generateName -> a constant placeholder.
# metadata.generateName without metadata.name is valid, server-generated-
# name Kubernetes; detection must never depend on a value only needed for
# display, or every sprintf building a violation message goes undefined
# along with it.
name := object.get(input.metadata, "name", object.get(input.metadata, "generateName", "<unnamed>"))

# Containers where security-context fields (privileged, allowPrivilegeEscalation,
# runAsNonRoot, etc.) are meaningful and checkable - regular, init, AND
# ephemeral containers all support a securityContext.
security_relevant_containers contains c if {
	c := regular_or_init_containers[_]
}

security_relevant_containers contains c if {
	c := input.spec.ephemeralContainers[_]
}

# Deployment-shaped ephemeral containers are deliberately not included:
# Kubernetes only adds ephemeral containers to an already-running Pod via
# the dedicated ephemeralcontainers subresource, never upfront in a
# Deployment's PodTemplateSpec at pod-creation time.

# Containers where resources.limits is a meaningful field to require.
# Ephemeral containers are excluded: the API server forbids a `resources`
# field on them outright, so requiring one would make any manifest with a
# debug ephemeral container permanently, unfixably non-compliant.
resource_managed_containers contains c if {
	c := regular_or_init_containers[_]
}

regular_or_init_containers contains c if {
	c := input.spec.containers[_]
}

regular_or_init_containers contains c if {
	c := input.spec.initContainers[_]
}

regular_or_init_containers contains c if {
	c := input.spec.template.spec.containers[_]
}

regular_or_init_containers contains c if {
	c := input.spec.template.spec.initContainers[_]
}

regular_or_init_containers contains c if {
	c := input.spec.jobTemplate.spec.template.spec.containers[_]
}

regular_or_init_containers contains c if {
	c := input.spec.jobTemplate.spec.template.spec.initContainers[_]
}

# True when any pod-shaped spec on this manifest sets runAsNonRoot at the
# pod level. Safe to check across all shapes at once: a real manifest only
# ever populates one of Pod/.template.spec/.jobTemplate.spec.template.spec.
pod_runs_as_non_root if {
	some s in all_pod_specs
	s.securityContext.runAsNonRoot == true
}

# True when any pod-shaped spec sets runAsUser: 0 - explicit root, which
# directly contradicts runAsNonRoot and which Kubernetes' Restricted Pod
# Security Standard separately prohibits regardless of that flag.
pod_run_as_user_is_zero if {
	some s in all_pod_specs
	s.securityContext.runAsUser == 0
}

# True when this manifest declares a Windows pod (spec.os.name: windows).
# Matters for allowPrivilegeEscalation specifically: the API server
# rejects a Windows Pod outright if that field is set at all, true or
# false, since Windows has no privilege-escalation concept to toggle.
is_windows_pod if {
	some s in all_pod_specs
	s.os.name == "windows"
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

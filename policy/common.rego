package common

# Shared helpers used by every policy package in this repo.
# Flattens the places a container can appear across the manifest kinds
# this repo checks (Pod, and Pod-template-shaped kinds like Deployment,
# StatefulSet, DaemonSet, Job, CronJob's jobTemplate).

# Falls back through name -> generateName -> a constant placeholder.
# metadata.generateName without metadata.name is valid, server-generated-name
# Kubernetes - confirmed directly: a Pod using generateName with
# hostNetwork, privileged, escalation, and a static credential passed every
# policy clean before this fallback existed, because name was undefined,
# which made every sprintf using it undefined, which made every deny rule
# referencing it silently disappear. Detection must never depend on a value
# that's only needed for display - same lesson as deny_public_iam_principal
# in the gcp-iam-baseline repo, missed here the first time around.
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

# Deployment-shaped ephemeral containers are deliberately NOT included here.
# Confirmed against Kubernetes' own docs: ephemeral containers can only be
# added to an already-running Pod through the dedicated ephemeralcontainers
# subresource, never declared upfront in a Deployment's PodTemplateSpec at
# pod-creation time. A field there is structurally meaningless, not a real
# input shape this repo needs to support.

# Containers where resources.limits is a meaningful field to require.
# Ephemeral containers are deliberately excluded - confirmed against
# Kubernetes' own ephemeral-container design: the API server forbids a
# `resources` field on an ephemeral container outright, so a policy that
# required it would make every manifest containing a debug ephemeral
# container permanently, unfixably non-compliant. Verified directly: an
# otherwise fully-hardened Pod failed only because its ephemeral debugger
# lacked resources.limits, a field Kubernetes itself does not let it have.
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

# True when any pod-shaped spec on this manifest sets runAsUser: 0 at the
# pod level - explicit root, which directly contradicts runAsNonRoot and
# which Kubernetes' Restricted Pod Security Standard separately
# prohibits. Confirmed directly: a Pod with pod-level runAsNonRoot: true
# AND a container explicitly setting runAsUser: 0 passed every policy in
# this repo clean - runAsNonRoot being a boolean flag was never cross-
# checked against an explicit root UID contradicting it.
pod_run_as_user_is_zero if {
	some s in all_pod_specs
	s.securityContext.runAsUser == 0
}

# True when this manifest declares a Windows pod (spec.os.name: windows).
# Matters for allowPrivilegeEscalation specifically: confirmed against
# Kubernetes' own Pod Security Standards docs, a Windows Pod is REJECTED
# by the API server outright if allowPrivilegeEscalation is set at all -
# true or false, doesn't matter, Windows has no privilege-escalation
# concept to toggle. A policy that requires setting it to false would
# demand the one thing the real API server forbids for a legitimate
# Windows workload.
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

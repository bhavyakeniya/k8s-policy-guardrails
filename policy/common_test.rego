package common

# Exhaustive input-shape matrix for the shared helpers every policy in this
# repo is built on. This exists because the CronJob init-container gap
# (confirmed: a privileged, as-root, no-limits, static-credential init
# container under a CronJob passed every policy clean) lived in exactly
# this file, and it lived here because no test exercised that specific
# shape directly - every existing test went through an individual policy
# instead of the shared helper, so a shape no policy's test happened to
# cover never got checked at all. Testing security_relevant_containers/
# resource_managed_containers/all_pod_specs directly, once, for every kind
# this repo claims to support, means a new policy built on top of these
# helpers inherits that coverage for free.

pod_regular := {"kind": "Pod", "metadata": {"name": "x"}, "spec": {"containers": [{"name": "regular"}]}}

pod_init := {"kind": "Pod", "metadata": {"name": "x"}, "spec": {"initContainers": [{"name": "init"}]}}

deployment_regular := {"kind": "Deployment", "metadata": {"name": "x"}, "spec": {"template": {"spec": {"containers": [{"name": "regular"}]}}}}

deployment_init := {"kind": "Deployment", "metadata": {"name": "x"}, "spec": {"template": {"spec": {"initContainers": [{"name": "init"}]}}}}

statefulset_regular := {"kind": "StatefulSet", "metadata": {"name": "x"}, "spec": {"template": {"spec": {"containers": [{"name": "regular"}]}}}}

statefulset_init := {"kind": "StatefulSet", "metadata": {"name": "x"}, "spec": {"template": {"spec": {"initContainers": [{"name": "init"}]}}}}

daemonset_regular := {"kind": "DaemonSet", "metadata": {"name": "x"}, "spec": {"template": {"spec": {"containers": [{"name": "regular"}]}}}}

daemonset_init := {"kind": "DaemonSet", "metadata": {"name": "x"}, "spec": {"template": {"spec": {"initContainers": [{"name": "init"}]}}}}

job_regular := {"kind": "Job", "metadata": {"name": "x"}, "spec": {"template": {"spec": {"containers": [{"name": "regular"}]}}}}

job_init := {"kind": "Job", "metadata": {"name": "x"}, "spec": {"template": {"spec": {"initContainers": [{"name": "init"}]}}}}

cronjob_regular := {"kind": "CronJob", "metadata": {"name": "x"}, "spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{"name": "regular"}]}}}}}}

cronjob_init := {"kind": "CronJob", "metadata": {"name": "x"}, "spec": {"jobTemplate": {"spec": {"template": {"spec": {"initContainers": [{"name": "init"}]}}}}}}

pod_ephemeral := {"kind": "Pod", "metadata": {"name": "x"}, "spec": {"ephemeralContainers": [{"name": "debug"}]}}

test_security_relevant_pod_regular if {
	{"regular"} == {c.name | some c in security_relevant_containers} with input as pod_regular
}

test_security_relevant_pod_init if {
	{"init"} == {c.name | some c in security_relevant_containers} with input as pod_init
}

test_security_relevant_pod_ephemeral if {
	{"debug"} == {c.name | some c in security_relevant_containers} with input as pod_ephemeral
}

test_security_relevant_deployment_regular if {
	{"regular"} == {c.name | some c in security_relevant_containers} with input as deployment_regular
}

test_security_relevant_deployment_init if {
	{"init"} == {c.name | some c in security_relevant_containers} with input as deployment_init
}

test_security_relevant_statefulset_regular if {
	{"regular"} == {c.name | some c in security_relevant_containers} with input as statefulset_regular
}

test_security_relevant_statefulset_init if {
	{"init"} == {c.name | some c in security_relevant_containers} with input as statefulset_init
}

test_security_relevant_daemonset_regular if {
	{"regular"} == {c.name | some c in security_relevant_containers} with input as daemonset_regular
}

test_security_relevant_daemonset_init if {
	{"init"} == {c.name | some c in security_relevant_containers} with input as daemonset_init
}

test_security_relevant_job_regular if {
	{"regular"} == {c.name | some c in security_relevant_containers} with input as job_regular
}

test_security_relevant_job_init if {
	{"init"} == {c.name | some c in security_relevant_containers} with input as job_init
}

test_security_relevant_cronjob_regular if {
	{"regular"} == {c.name | some c in security_relevant_containers} with input as cronjob_regular
}

# This is the exact shape that was silently uncovered before this policy
# existed - see the module docstring above.
test_security_relevant_cronjob_init if {
	{"init"} == {c.name | some c in security_relevant_containers} with input as cronjob_init
}

# resource_managed_containers must match security_relevant_containers for
# every non-ephemeral shape (same underlying regular_or_init_containers),
# and must NOT include ephemeral containers at all - that exclusion is the
# whole point of splitting the helper. Confirmed directly: before the
# split, an otherwise fully-hardened Pod failed resource_limits solely
# because its ephemeral debugger lacked resources.limits, a field
# Kubernetes forbids on ephemeral containers entirely.
test_resource_managed_pod_regular if {
	{"regular"} == {c.name | some c in resource_managed_containers} with input as pod_regular
}

test_resource_managed_cronjob_init if {
	{"init"} == {c.name | some c in resource_managed_containers} with input as cronjob_init
}

test_resource_managed_excludes_ephemeral if {
	count(resource_managed_containers) == 0 with input as pod_ephemeral
}

test_all_pod_specs_pod if {
	count(all_pod_specs) == 1 with input as pod_regular
}

test_all_pod_specs_deployment if {
	count(all_pod_specs) == 1 with input as deployment_regular
}

test_all_pod_specs_statefulset if {
	count(all_pod_specs) == 1 with input as statefulset_regular
}

test_all_pod_specs_daemonset if {
	count(all_pod_specs) == 1 with input as daemonset_regular
}

test_all_pod_specs_job if {
	count(all_pod_specs) == 1 with input as job_regular
}

test_all_pod_specs_cronjob if {
	count(all_pod_specs) == 1 with input as cronjob_regular
}

# name falls back through name -> generateName -> a constant placeholder.
# Confirmed directly: a Pod using generateName instead of name, with
# hostNetwork/privileged/escalation/a static credential, passed every
# policy clean (12/12) before this fallback existed, because every
# sprintf building a violation message needed `name` and silently went
# undefined without it.
test_name_prefers_metadata_name if {
	"explicit" == name with input as {"metadata": {"name": "explicit", "generateName": "ignored-"}}
}

test_name_falls_back_to_generate_name if {
	"generated-" == name with input as {"metadata": {"generateName": "generated-"}}
}

test_name_falls_back_to_placeholder_when_neither_present if {
	"<unnamed>" == name with input as {"metadata": {}}
}

test_is_windows_pod_true if {
	is_windows_pod with input as {"kind": "Pod", "metadata": {"name": "x"}, "spec": {"os": {"name": "windows"}, "containers": [{"name": "app"}]}}
}

test_is_windows_pod_false_when_linux if {
	not is_windows_pod with input as {"kind": "Pod", "metadata": {"name": "x"}, "spec": {"os": {"name": "linux"}, "containers": [{"name": "app"}]}}
}

test_is_windows_pod_false_when_unset if {
	not is_windows_pod with input as pod_regular
}

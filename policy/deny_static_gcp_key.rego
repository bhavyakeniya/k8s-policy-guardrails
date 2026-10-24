package policies.static_gcp_key

import data.common

# GCP Workload Identity hardening (no single CIS Kubernetes control; aligns
# with the CIS Google Cloud Platform Benchmark's guidance to avoid
# long-lived service-account keys). Mounting a GCP JSON key as a Secret, or
# pointing GOOGLE_APPLICATION_CREDENTIALS at one, defeats Workload Identity
# Federation and leaves a long-lived credential sitting in etcd.
#
# Known limitation: the secret-volume check below matches on the Secret's
# *name* (containing "gcp-key" or "service-account-key"), not its actual
# contents - this policy only ever sees a Pod/Deployment manifest, not the
# referenced Secret object's data. A Secret named e.g. "db-creds" that still
# holds a GCP key would slip past this rule. Closing that gap for real needs
# conftest's --combine mode so a policy can cross-reference the Secret's own
# `type`/`data` keys against every Pod that mounts it - out of scope for
# this repo, called out here rather than silently left unfixed.

deny contains msg if {
	container := common.security_relevant_containers[_]
	env := container.env[_]
	env.name == "GOOGLE_APPLICATION_CREDENTIALS"
	msg := sprintf("%s/%s: container %q sets GOOGLE_APPLICATION_CREDENTIALS; use Workload Identity Federation instead of a mounted key", [input.kind, common.name, container.name])
}

static_key_name_patterns := ["gcp-key", "service-account-key", "sa-key", "key.json"]

# Secret names from both volume shapes Kubernetes supports - a directly
# mounted Secret volume (volume.secret.secretName) and a projected volume
# (volume.projected.sources[].secret.name). Confirmed directly: a hardened
# Pod mounting the exact same "my-gcp-key" Secret through the projected
# shape instead of the direct one passed clean, because only the direct
# shape was checked. Both shapes feed the same naming heuristic once below
# rather than duplicating it per volume type.
secret_volume_names contains name if {
	spec := common.all_pod_specs[_]
	volume := spec.volumes[_]
	name := volume.secret.secretName
}

secret_volume_names contains name if {
	spec := common.all_pod_specs[_]
	volume := spec.volumes[_]
	source := volume.projected.sources[_]
	name := source.secret.name
}

# Token-boundary matched, not a plain substring - confirmed directly as a
# real false positive: "tls-rsa-key" contains the literal substring
# "sa-key" (inside "rsa-key"), so a plain contains() check rejected a
# hardened Pod that mounted an ordinary TLS secret, for a reason that had
# nothing to do with GCP. "(^|[-.])pattern([-.]|$)" requires the pattern to
# be its own token, delimited by the name's start/end or a "-"/".", so
# "rsa-key" no longer satisfies "sa-key" the same way "my-gcp-key" still
# satisfies "gcp-key". Applied to every pattern, not just the one reported
# false positive - "gcp-key" alone could just as easily mismatch inside an
# unrelated name like "gcp-keyboard-config".
deny contains msg if {
	name := secret_volume_names[_]
	pattern := static_key_name_patterns[_]
	escaped_pattern := regex.replace(pattern, `\.`, `\.`)
	regex.match(sprintf(`(^|[-.])%s([-.]|$)`, [escaped_pattern]), lower(name))
	msg := sprintf("%s/%s: a volume mounts secret %q, matching %q; use Workload Identity Federation instead of a static key", [input.kind, common.name, name, pattern])
}

# deny_malformed_workload_identity_annotation, not
# deny_missing_workload_identity_annotation - deliberately. This used to
# deny every ServiceAccount that lacked the annotation at all, which was
# wrong on three counts, confirmed against GKE's own docs rather than
# assumed: (1) not every ServiceAccount needs GCP API access in the first
# place - most don't; (2) GKE also supports granting IAM permissions
# directly to a Kubernetes ServiceAccount's principal identifier, which
# uses no iam.gke.io annotation at all; (3) even where the annotation IS
# the right mechanism (GCP service-account impersonation), the annotation
# alone doesn't prove Workload Identity is wired up - the IAM-side
# workloadIdentityUser binding on the GCP service account also has to
# exist, and that lives in Terraform/gcloud state this policy can never
# see from a Kubernetes manifest alone. Denying on absence punished every
# unrelated ServiceAccount and forced a self-service
# policy.guardrails/exempt label with zero governance to work around it.
# What IS still a real, visible-from-the-manifest mistake: a ServiceAccount
# that HAS the annotation but with a malformed value - that's unambiguous
# regardless of which Workload Identity pattern is in use.
# Matches Google's actual service-account-ID grammar for both the SA-id
# and project-id components - [a-z]([-a-z0-9]*[a-z0-9])?, 6-30 characters
# total - checked against GCP's own documented requirements rather than
# assumed. The previous regex only validated the domain suffix and the
# absence of whitespace, so `!!!@???.iam.gserviceaccount.com` passed it;
# confirmed directly before fixing. This intentionally does NOT accept the
# legacy default-compute-service-account format
# (N-compute@developer.gserviceaccount.com) - Google's own Workload
# Identity guidance recommends a dedicated service account over the
# default compute one, so rejecting that format here is a feature, not a
# gap.
gsa_component := `[a-z][-a-z0-9]{4,28}[a-z0-9]`

deny contains msg if {
	input.kind == "ServiceAccount"
	annotation := input.metadata.annotations["iam.gke.io/gcp-service-account"]
	not regex.match(sprintf(`^%s@%s\.iam\.gserviceaccount\.com$`, [gsa_component, gsa_component]), annotation)
	msg := sprintf("ServiceAccount/%s: iam.gke.io/gcp-service-account annotation %q does not match Google's service-account-ID grammar ([a-z]([-a-z0-9]*[a-z0-9])?, 6-30 chars, for both the account and project components) - note that this check cannot confirm Workload Identity is actually wired up end-to-end (the IAM-side binding lives outside this manifest), only that the annotation, if present, is well-formed", [common.name, annotation])
}

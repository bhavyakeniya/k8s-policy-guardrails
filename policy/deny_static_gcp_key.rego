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
	container := common.all_containers[_]
	env := container.env[_]
	env.name == "GOOGLE_APPLICATION_CREDENTIALS"
	msg := sprintf("%s/%s: container %q sets GOOGLE_APPLICATION_CREDENTIALS; use Workload Identity Federation instead of a mounted key", [input.kind, common.name, container.name])
}

static_key_name_patterns := ["gcp-key", "service-account-key", "sa-key", "key.json"]

deny contains msg if {
	spec := common.all_pod_specs[_]
	volume := spec.volumes[_]
	volume.secret.secretName
	pattern := static_key_name_patterns[_]
	contains(lower(volume.secret.secretName), pattern)
	msg := sprintf("%s/%s: volume %q mounts a secret matching %q; use Workload Identity Federation instead of a static key", [input.kind, common.name, volume.name, pattern])
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
deny contains msg if {
	input.kind == "ServiceAccount"
	annotation := input.metadata.annotations["iam.gke.io/gcp-service-account"]
	not regex.match(`^[^@\s]+@[^@\s]+\.iam\.gserviceaccount\.com$`, annotation)
	msg := sprintf("ServiceAccount/%s: iam.gke.io/gcp-service-account annotation %q is not a valid *.iam.gserviceaccount.com email - note that this check cannot confirm Workload Identity is actually wired up end-to-end (the IAM-side binding lives outside this manifest), only that the annotation, if present, is well-formed", [common.name, annotation])
}

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

deny contains msg if {
	input.kind == "ServiceAccount"
	not input.metadata.labels["policy.guardrails/exempt"] == "true"
	not has_valid_workload_identity_annotation
	msg := sprintf("ServiceAccount/%s: missing or malformed iam.gke.io/gcp-service-account annotation (expected a *.iam.gserviceaccount.com email); either bind it to Workload Identity or label it policy.guardrails/exempt: \"true\"", [common.name])
}

has_valid_workload_identity_annotation if {
	regex.match(`^[^@\s]+@[^@\s]+\.iam\.gserviceaccount\.com$`, input.metadata.annotations["iam.gke.io/gcp-service-account"])
}

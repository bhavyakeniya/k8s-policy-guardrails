package policies.static_gcp_key

import data.common

# GCP Workload Identity hardening (no single CIS Kubernetes control; aligns
# with the CIS Google Cloud Platform Benchmark's guidance to avoid
# long-lived service-account keys). Mounting a GCP JSON key as a Secret, or
# pointing GOOGLE_APPLICATION_CREDENTIALS at one, defeats Workload Identity
# Federation and leaves a long-lived credential sitting in etcd.

deny contains msg if {
	container := common.all_containers[_]
	env := container.env[_]
	env.name == "GOOGLE_APPLICATION_CREDENTIALS"
	msg := sprintf("%s/%s: container %q sets GOOGLE_APPLICATION_CREDENTIALS; use Workload Identity Federation instead of a mounted key", [input.kind, common.name, container.name])
}

deny contains msg if {
	spec := common.all_pod_specs[_]
	volume := spec.volumes[_]
	volume.secret.secretName
	contains(lower(volume.secret.secretName), "gcp-key")
	msg := sprintf("%s/%s: volume %q mounts a secret matching 'gcp-key'; use Workload Identity Federation instead of a static key", [input.kind, common.name, volume.name])
}

deny contains msg if {
	input.kind == "ServiceAccount"
	not input.metadata.annotations["iam.gke.io/gcp-service-account"]
	not input.metadata.labels["policy.guardrails/exempt"] == "true"
	msg := sprintf("ServiceAccount/%s: missing iam.gke.io/gcp-service-account annotation; either bind it to Workload Identity or label it policy.guardrails/exempt: \"true\"", [common.name])
}

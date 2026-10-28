package policies.static_gcp_key

import data.common

# GCP Workload Identity hardening (no single CIS Kubernetes control; aligns
# with the CIS Google Cloud Platform Benchmark's guidance to avoid
# long-lived service-account keys).
#
# Known limitation: the secret-volume checks below match on names visible
# in the manifest, not the Secret object's actual contents - a Secret
# named e.g. "db-creds" that still holds a GCP key slips past. Closing
# that for real needs conftest's --combine mode to cross-reference the
# Secret's own type/data against every Pod that mounts it; out of scope
# here.

# A blanket ban on file-based ADC, not static-key detection: this env var
# can legitimately point at a Workload/Workforce Identity Federation
# config with no key material at all (per Google's ADC docs), not only a
# service-account key. GKE's native Workload Identity (the metadata-
# server mechanism, checked by the ServiceAccount annotation rule below)
# needs no file on disk at all, so any file-based ADC mechanism - key or
# federation config alike - is disallowed as a mountable attack surface
# the metadata-server mechanism doesn't have.
deny contains msg if {
	container := common.security_relevant_containers[_]
	env := container.env[_]
	env.name == "GOOGLE_APPLICATION_CREDENTIALS"
	msg := sprintf("%s/%s: container %q sets GOOGLE_APPLICATION_CREDENTIALS - file-based ADC of any kind (service-account key or Workload/Workforce Identity Federation config) is disallowed in favor of GKE's native Workload Identity, which needs no credential file on disk", [input.kind, common.name, container.name])
}

static_key_name_patterns := ["gcp-key", "service-account-key", "sa-key", "key.json"]

# Secret names from both volume shapes Kubernetes supports: a direct
# Secret volume (volume.secret.secretName) and a projected volume
# (volume.projected.sources[].secret.name).
secret_reference_names contains name if {
	spec := common.all_pod_specs[_]
	volume := spec.volumes[_]
	name := volume.secret.secretName
}

secret_reference_names contains name if {
	spec := common.all_pod_specs[_]
	volume := spec.volumes[_]
	source := volume.projected.sources[_]
	name := source.secret.name
}

# secret.items[]/projected source.secret.items[] can rename a key to an
# explicit mount path - that path is a visible filename in the manifest,
# not hidden Secret content, so it gets the same naming check as the
# Secret's own name.
secret_reference_names contains name if {
	spec := common.all_pod_specs[_]
	volume := spec.volumes[_]
	item := volume.secret.items[_]
	name := item.key
}

# items[].path can contain directory components (e.g. "my-group/key.json"
# - Kubernetes explicitly supports this), so the filename that actually
# carries a suspicious name can be preceded by "/" rather than a
# "-"/"."/"_" boundary. basename() takes the last path segment before the
# naming check runs, same as it would for a Secret name or a bare key
# with no "/" in it at all.
basename(path) := result if {
	parts := split(path, "/")
	result := parts[count(parts) - 1]
}

secret_reference_names contains name if {
	spec := common.all_pod_specs[_]
	volume := spec.volumes[_]
	item := volume.secret.items[_]
	name := basename(item.path)
}

secret_reference_names contains name if {
	spec := common.all_pod_specs[_]
	volume := spec.volumes[_]
	source := volume.projected.sources[_]
	item := source.secret.items[_]
	name := item.key
}

secret_reference_names contains name if {
	spec := common.all_pod_specs[_]
	volume := spec.volumes[_]
	source := volume.projected.sources[_]
	item := source.secret.items[_]
	name := basename(item.path)
}

# A Secret doesn't have to come in through a volume at all - Kubernetes
# also supports injecting one directly as an environment variable, via
# either a single key (env[].valueFrom.secretKeyRef) or every key at once
# (envFrom[].secretRef). Both the Secret's own name and, for secretKeyRef,
# the specific key referenced get the same naming check as a volume-based
# reference.
secret_reference_names contains name if {
	container := common.security_relevant_containers[_]
	env := container.env[_]
	name := env.valueFrom.secretKeyRef.name
}

secret_reference_names contains name if {
	container := common.security_relevant_containers[_]
	env := container.env[_]
	name := env.valueFrom.secretKeyRef.key
}

secret_reference_names contains name if {
	container := common.security_relevant_containers[_]
	envFrom := container.envFrom[_]
	name := envFrom.secretRef.name
}

# Token-boundary matched, not a plain substring: "(^|[-._])pattern([-._]|$)"
# requires the pattern to be its own token delimited by the name's
# start/end or a "-"/"."/"_", so e.g. "tls-rsa-key" doesn't match "sa-key"
# the way "my-gcp-key" matches "gcp-key" - "_" is included because
# Secret/ConfigMap item keys allow it even though Secret object names
# don't ("prod_sa-key" is a valid key). suspicious_secret_names is a SET
# of names, not of (name, pattern) pairs, so a name matching several
# patterns at once (e.g. "gcp-key.json") still produces one violation.
suspicious_secret_names contains name if {
	name := secret_reference_names[_]
	pattern := static_key_name_patterns[_]
	escaped_pattern := regex.replace(pattern, `\.`, `\.`)
	regex.match(sprintf(`(^|[-._])%s([-._]|$)`, [escaped_pattern]), lower(name))
}

deny contains msg if {
	name := suspicious_secret_names[_]
	msg := sprintf("%s/%s: a volume or environment variable references %q (as a Secret name, an items[].key, an items[].path, or a secretKeyRef/secretRef key), matching a static-key naming pattern; use Workload Identity Federation instead of a static key", [input.kind, common.name, name])
}

# Deliberately checks for a malformed annotation, not a missing one.
# Denying on absence would punish every ServiceAccount that doesn't need
# GCP access (most don't) and that GKE's annotation-free direct-principal
# binding doesn't use anyway. Even where the annotation is the right
# mechanism, it alone can't prove the IAM-side workloadIdentityUser
# binding exists - that lives outside this manifest. A malformed value,
# though, is unambiguous regardless of which pattern is in use.
#
# gsa_component matches Google's actual service-account-ID grammar for
# both the SA-id and project-id components -
# [a-z]([-a-z0-9]*[a-z0-9])?, 6-30 characters - rather than just checking
# for an "@" and the right domain suffix. Deliberately does not accept
# the legacy default-compute-service-account format
# (N-compute@developer.gserviceaccount.com); Google's own guidance
# recommends a dedicated service account for Workload Identity instead.
gsa_component := `[a-z][-a-z0-9]{4,28}[a-z0-9]`

deny contains msg if {
	input.kind == "ServiceAccount"
	annotation := input.metadata.annotations["iam.gke.io/gcp-service-account"]
	not regex.match(sprintf(`^%s@%s\.iam\.gserviceaccount\.com$`, [gsa_component, gsa_component]), annotation)
	msg := sprintf("ServiceAccount/%s: iam.gke.io/gcp-service-account annotation %q does not match Google's service-account-ID grammar ([a-z]([-a-z0-9]*[a-z0-9])?, 6-30 chars, for both the account and project components) - this check cannot confirm Workload Identity is wired up end-to-end, only that the annotation, if present, is well-formed", [common.name, annotation])
}

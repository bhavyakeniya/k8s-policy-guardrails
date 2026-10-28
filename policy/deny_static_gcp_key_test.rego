package policies.static_gcp_key

test_google_application_credentials_env_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {"containers": [{"name": "app", "env": [{"name": "GOOGLE_APPLICATION_CREDENTIALS", "value": "/secrets/key.json"}]}]},
	}
	count(deny) > 0 with input as mock_input
}

# Reproduced directly: this path is a legitimate Workload Identity
# Federation config, not a static key - confirmed against Google's own
# ADC docs. Still denied, but the message now says this is a blanket
# file-based-ADC ban, not a claim that a key was detected.
test_google_application_credentials_pointing_at_wif_config_still_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {"containers": [{"name": "app", "env": [{"name": "GOOGLE_APPLICATION_CREDENTIALS", "value": "/var/run/google/wif-credential-config.json"}]}]},
	}
	count(deny) > 0 with input as mock_input
}

test_gcp_key_secret_volume_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {
			"containers": [{"name": "app"}],
			"volumes": [{"name": "creds", "secret": {"secretName": "my-gcp-key"}}],
		},
	}
	count(deny) > 0 with input as mock_input
}

# Confirmed as a real bypass before projected-volume support existed: a
# hardened Pod mounting the exact same Secret through the projected shape
# instead of the direct one passed clean (12/12).
test_gcp_key_projected_secret_volume_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {
			"containers": [{"name": "app"}],
			"volumes": [{"name": "creds", "projected": {"sources": [{"secret": {"name": "my-gcp-key"}}]}}],
		},
	}
	count(deny) > 0 with input as mock_input
}

test_gcp_key_projected_secret_volume_in_deployment_template_denied if {
	mock_input := {
		"kind": "Deployment",
		"metadata": {"name": "bad-deploy"},
		"spec": {"template": {"spec": {
			"containers": [{"name": "app"}],
			"volumes": [{"name": "creds", "projected": {"sources": [{"secret": {"name": "my-gcp-key"}}]}}],
		}}},
	}
	count(deny) > 0 with input as mock_input
}

# Confirmed as a real bypass before items[] inspection existed: the
# suspicious filename was already visible in the manifest, just not in
# secretName.
test_direct_secret_items_key_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {
			"containers": [{"name": "app"}],
			"volumes": [{"name": "creds", "secret": {"secretName": "db-creds", "items": [{"key": "gcp-key", "path": "irrelevant.txt"}]}}],
		},
	}
	count(deny) > 0 with input as mock_input
}

test_direct_secret_items_path_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {
			"containers": [{"name": "app"}],
			"volumes": [{"name": "creds", "secret": {"secretName": "db-creds", "items": [{"key": "irrelevant", "path": "key.json"}]}}],
		},
	}
	count(deny) > 0 with input as mock_input
}

test_projected_secret_items_path_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {
			"containers": [{"name": "app"}],
			"volumes": [{"name": "creds", "projected": {"sources": [{"secret": {"name": "db-creds", "items": [{"key": "irrelevant", "path": "key.json"}]}}]}}],
		},
	}
	count(deny) > 0 with input as mock_input
}

# Confirmed as a real bypass before basename extraction existed:
# Kubernetes explicitly supports directory components in items[].path.
test_nested_secret_path_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {
			"containers": [{"name": "app"}],
			"volumes": [{"name": "creds", "secret": {"secretName": "db-creds", "items": [{"key": "credential", "path": "google/key.json"}]}}],
		},
	}
	count(deny) > 0 with input as mock_input
}

test_deeply_nested_secret_path_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {
			"containers": [{"name": "app"}],
			"volumes": [{"name": "creds", "projected": {"sources": [{"secret": {"name": "db-creds", "items": [{"key": "irrelevant", "path": "a/b/c/gcp-key"}]}}]}}],
		},
	}
	count(deny) > 0 with input as mock_input
}

test_nested_path_without_suspicious_basename_allowed if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "good-pod"},
		"spec": {
			"containers": [{"name": "app"}],
			"volumes": [{"name": "creds", "secret": {"secretName": "db-creds", "items": [{"key": "credential", "path": "google/username.txt"}]}}],
		},
	}
	count(deny) == 0 with input as mock_input
}

# Confirmed as a real bypass before "_" was a boundary character: Secret
# item keys allow underscores even though Secret object names don't.
test_underscore_delimited_key_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {
			"containers": [{"name": "app"}],
			"volumes": [{"name": "creds", "secret": {"secretName": "db-creds", "items": [{"key": "prod_sa-key", "path": "irrelevant.txt"}]}}],
		},
	}
	count(deny) > 0 with input as mock_input
}

# Confirmed as a real bypass before env/envFrom secret references were
# inspected: Kubernetes officially supports injecting a Secret via
# secretKeyRef/secretRef, not only through a volume.
test_env_secret_key_ref_name_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {"containers": [{"name": "app", "env": [{"name": "X", "valueFrom": {"secretKeyRef": {"name": "prod-gcp-key", "key": "irrelevant"}}}]}]},
	}
	count(deny) > 0 with input as mock_input
}

test_env_secret_key_ref_key_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {"containers": [{"name": "app", "env": [{"name": "X", "valueFrom": {"secretKeyRef": {"name": "db-creds", "key": "service-account-key.json"}}}]}]},
	}
	count(deny) > 0 with input as mock_input
}

test_envfrom_secret_ref_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {"containers": [{"name": "app", "envFrom": [{"secretRef": {"name": "service-account-key"}}]}]},
	}
	count(deny) > 0 with input as mock_input
}

test_init_container_env_secret_key_ref_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {
			"containers": [{"name": "app"}],
			"initContainers": [{"name": "init-app", "env": [{"name": "X", "valueFrom": {"secretKeyRef": {"name": "prod-gcp-key", "key": "irrelevant"}}}]}],
		},
	}
	count(deny) > 0 with input as mock_input
}

test_ephemeral_container_envfrom_secret_ref_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {
			"containers": [{"name": "app"}],
			"ephemeralContainers": [{"name": "debug", "envFrom": [{"secretRef": {"name": "service-account-key"}}]}],
		},
	}
	count(deny) > 0 with input as mock_input
}

test_env_secret_ref_without_suspicious_name_allowed if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "good-pod"},
		"spec": {"containers": [{"name": "app", "env": [{"name": "X", "valueFrom": {"secretKeyRef": {"name": "db-creds", "key": "username"}}}]}]},
	}
	count(deny) == 0 with input as mock_input
}

test_secret_items_without_suspicious_names_allowed if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "good-pod"},
		"spec": {
			"containers": [{"name": "app"}],
			"volumes": [{"name": "creds", "secret": {"secretName": "db-creds", "items": [{"key": "username", "path": "username.txt"}]}}],
		},
	}
	count(deny) == 0 with input as mock_input
}

test_projected_volume_with_non_secret_source_allowed if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "good-pod"},
		"spec": {
			"containers": [{"name": "app"}],
			"volumes": [{"name": "cfg", "projected": {"sources": [{"configMap": {"name": "app-config"}}]}}],
		},
	}
	count(deny) == 0 with input as mock_input
}

# Confirmed as a real false positive before token-boundary matching
# existed: "tls-rsa-key" contains the literal substring "sa-key" (inside
# "rsa-key"), so an otherwise hardened Pod mounting an ordinary TLS secret
# was rejected for a reason that had nothing to do with GCP.
test_tls_rsa_key_not_flagged_as_sa_key_false_positive if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "good-pod"},
		"spec": {
			"containers": [{"name": "app"}],
			"volumes": [{"name": "tls", "secret": {"secretName": "tls-rsa-key"}}],
		},
	}
	count(deny) == 0 with input as mock_input
}

test_gcp_keyboard_not_flagged_as_gcp_key_false_positive if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "good-pod"},
		"spec": {
			"containers": [{"name": "app"}],
			"volumes": [{"name": "cfg", "secret": {"secretName": "mygcp-keyboard-config"}}],
		},
	}
	count(deny) == 0 with input as mock_input
}

test_exact_sa_key_still_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {
			"containers": [{"name": "app"}],
			"volumes": [{"name": "creds", "secret": {"secretName": "legacy-sa-key"}}],
		},
	}
	count(deny) > 0 with input as mock_input
}

# Confirmed as a real duplicate before suspicious_secret_names deduped by
# name: "gcp-key.json" matches both the "gcp-key" and "key.json" patterns,
# and produced two separate deny messages for the same volume.
test_overlapping_patterns_produce_exactly_one_violation if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {
			"containers": [{"name": "app"}],
			"volumes": [{"name": "creds", "secret": {"secretName": "gcp-key.json"}}],
		},
	}
	count(deny) == 1 with input as mock_input
}

test_key_dot_json_pattern_still_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {
			"containers": [{"name": "app"}],
			"volumes": [{"name": "creds", "secret": {"secretName": "backup-key.json"}}],
		},
	}
	count(deny) > 0 with input as mock_input
}

test_service_account_key_named_volume_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {
			"containers": [{"name": "app"}],
			"volumes": [{"name": "creds", "secret": {"secretName": "billing-service-account-key"}}],
		},
	}
	count(deny) > 0 with input as mock_input
}

test_service_account_without_annotation_at_all_is_allowed if {
	# Not every ServiceAccount needs GCP access, and GKE's newer
	# direct-principal binding doesn't use this annotation at all - absence
	# alone is not evidence of a mistake. Confirmed as a real bug in the
	# old behavior: this used to deny every unrelated ServiceAccount.
	mock_input := {
		"kind": "ServiceAccount",
		"metadata": {"name": "app-sa", "annotations": {}},
	}
	count(deny) == 0 with input as mock_input
}

test_service_account_with_no_annotations_key_at_all_is_allowed if {
	mock_input := {
		"kind": "ServiceAccount",
		"metadata": {"name": "app-sa"},
	}
	count(deny) == 0 with input as mock_input
}

test_service_account_empty_annotation_denied if {
	mock_input := {
		"kind": "ServiceAccount",
		"metadata": {"name": "app-sa", "annotations": {"iam.gke.io/gcp-service-account": ""}},
	}
	count(deny) > 0 with input as mock_input
}

test_service_account_malformed_annotation_denied if {
	mock_input := {
		"kind": "ServiceAccount",
		"metadata": {"name": "app-sa", "annotations": {"iam.gke.io/gcp-service-account": "not-an-email"}},
	}
	count(deny) > 0 with input as mock_input
}

# "not-an-email" above doesn't even contain an "@", so the OLD permissive
# regex (which only checked for an "@" and the right domain suffix) would
# have rejected it too - a regression back to that old regex could stay
# green against this suite alone. This preserves the exact string the old
# regex accepted, confirmed directly before the grammar fix, so a
# regression is caught here specifically.
test_old_regex_exploit_string_denied if {
	mock_input := {
		"kind": "ServiceAccount",
		"metadata": {"name": "app-sa", "annotations": {"iam.gke.io/gcp-service-account": "!!!@???.iam.gserviceaccount.com"}},
	}
	count(deny) > 0 with input as mock_input
}

test_service_account_id_minimum_length_6_allowed if {
	mock_input := {
		"kind": "ServiceAccount",
		"metadata": {"name": "app-sa", "annotations": {"iam.gke.io/gcp-service-account": "abcdef@abcdef.iam.gserviceaccount.com"}},
	}
	count(deny) == 0 with input as mock_input
}

test_service_account_id_maximum_length_30_allowed if {
	mock_input := {
		"kind": "ServiceAccount",
		"metadata": {"name": "app-sa", "annotations": {"iam.gke.io/gcp-service-account": "abbbbbbbbbbbbbbbbbbbbbbbbbbbbz@my-project.iam.gserviceaccount.com"}},
	}
	count(deny) == 0 with input as mock_input
}

test_service_account_id_overlength_31_denied if {
	mock_input := {
		"kind": "ServiceAccount",
		"metadata": {"name": "app-sa", "annotations": {"iam.gke.io/gcp-service-account": "abbbbbbbbbbbbbbbbbbbbbbbbbbbbbz@my-project.iam.gserviceaccount.com"}},
	}
	count(deny) > 0 with input as mock_input
}

test_service_account_uppercase_denied if {
	mock_input := {
		"kind": "ServiceAccount",
		"metadata": {"name": "app-sa", "annotations": {"iam.gke.io/gcp-service-account": "App-sa@my-project.iam.gserviceaccount.com"}},
	}
	count(deny) > 0 with input as mock_input
}

test_service_account_leading_hyphen_denied if {
	mock_input := {
		"kind": "ServiceAccount",
		"metadata": {"name": "app-sa", "annotations": {"iam.gke.io/gcp-service-account": "-appsa@my-project.iam.gserviceaccount.com"}},
	}
	count(deny) > 0 with input as mock_input
}

test_service_account_trailing_hyphen_denied if {
	mock_input := {
		"kind": "ServiceAccount",
		"metadata": {"name": "app-sa", "annotations": {"iam.gke.io/gcp-service-account": "appsa-@my-project.iam.gserviceaccount.com"}},
	}
	count(deny) > 0 with input as mock_input
}

test_service_account_with_workload_identity_allowed if {
	mock_input := {
		"kind": "ServiceAccount",
		"metadata": {"name": "app-sa", "annotations": {"iam.gke.io/gcp-service-account": "app-sa@project.iam.gserviceaccount.com"}},
	}
	count(deny) == 0 with input as mock_input
}

test_pod_without_workload_identity_env_is_unaffected if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "good-pod"},
		"spec": {"containers": [{"name": "app"}]},
	}
	count(deny) == 0 with input as mock_input
}

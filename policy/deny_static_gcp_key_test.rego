package policies.static_gcp_key

test_google_application_credentials_env_denied if {
	mock_input := {
		"kind": "Pod",
		"metadata": {"name": "bad-pod"},
		"spec": {"containers": [{"name": "app", "env": [{"name": "GOOGLE_APPLICATION_CREDENTIALS", "value": "/secrets/key.json"}]}]},
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

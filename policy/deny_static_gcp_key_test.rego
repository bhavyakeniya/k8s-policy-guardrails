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

test_service_account_without_workload_identity_denied if {
	mock_input := {
		"kind": "ServiceAccount",
		"metadata": {"name": "app-sa", "annotations": {}},
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

test_service_account_exempt_label_allowed if {
	mock_input := {
		"kind": "ServiceAccount",
		"metadata": {"name": "default", "annotations": {}, "labels": {"policy.guardrails/exempt": "true"}},
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

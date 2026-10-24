package policies.reject_list_input

test_list_kind_denied if {
	mock_input := {"kind": "List", "items": [{"kind": "Pod", "metadata": {"name": "x"}, "spec": {"containers": [{"name": "app", "securityContext": {"privileged": true}}]}}]}
	count(deny) > 0 with input as mock_input
}

# Confirmed as a real bypass before this test existed: a privileged,
# host-networked Pod wrapped in kind: PodList passed 11/11, because the
# old rule only checked input.kind == "List" literally.
test_podlist_kind_denied if {
	mock_input := {"kind": "PodList", "items": [{"kind": "Pod", "metadata": {"name": "x"}, "spec": {"containers": [{"name": "app", "securityContext": {"privileged": true}}]}}]}
	count(deny) > 0 with input as mock_input
}

test_deploymentlist_kind_denied if {
	mock_input := {"kind": "DeploymentList", "items": [{"kind": "Deployment", "metadata": {"name": "x"}}]}
	count(deny) > 0 with input as mock_input
}

test_pod_kind_allowed if {
	mock_input := {"kind": "Pod", "metadata": {"name": "x"}, "spec": {"containers": [{"name": "app"}]}}
	count(deny) == 0 with input as mock_input
}

# A kind ending in "List" without an items array isn't a collection shape -
# make sure the items check actually gates the rule, not just the suffix.
test_kind_ending_in_list_without_items_allowed if {
	mock_input := {"kind": "SomethingList", "metadata": {"name": "x"}}
	count(deny) == 0 with input as mock_input
}

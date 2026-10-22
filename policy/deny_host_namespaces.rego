package policies.host_namespaces

import data.common

# CIS Kubernetes Benchmark, Pod Security Policies section ("prevent host
# namespace sharing": hostNetwork/hostPID/hostIPC) - see deny_privileged.rego
# for why no specific control number is cited.

deny contains msg if {
	spec := common.all_pod_specs[_]
	spec.hostNetwork == true
	msg := sprintf("%s/%s: hostNetwork must not be true", [input.kind, common.name])
}

deny contains msg if {
	spec := common.all_pod_specs[_]
	spec.hostPID == true
	msg := sprintf("%s/%s: hostPID must not be true", [input.kind, common.name])
}

deny contains msg if {
	spec := common.all_pod_specs[_]
	spec.hostIPC == true
	msg := sprintf("%s/%s: hostIPC must not be true", [input.kind, common.name])
}

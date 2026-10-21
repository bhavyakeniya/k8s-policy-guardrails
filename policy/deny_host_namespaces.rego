package policies.host_namespaces

import data.common

# CIS Kubernetes Benchmark 5.2.4 - hostNetwork
# CIS Kubernetes Benchmark 5.2.2 - hostPID
# CIS Kubernetes Benchmark 5.2.3 - hostIPC

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

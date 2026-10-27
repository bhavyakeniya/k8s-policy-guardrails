#!/usr/bin/env bash
# The single entry point for every gate this repo enforces - CI calls
# exactly this script, so "it passed locally" and "it passed in CI" mean
# the same thing. That claim only holds if the installed tool versions
# actually match what CI pins, not just that the tools exist - confirmed
# as a real gap: local OPA was 1.21.3 while CI pinned 1.21.1, unchecked.
# Requires opa, conftest, and kubeconform on PATH (see README Prerequisites).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source scripts/tool-versions.sh

check_version() {
  local tool="$1" actual="$2" expected="$3"
  if [[ "$actual" != "$expected" ]]; then
    echo "FAIL: $tool is $actual locally but this repo pins $expected (see scripts/tool-versions.sh)." >&2
    echo "      A language or validation change in $tool between these versions could pass" >&2
    echo "      locally and fail in CI, or vice versa. Install the pinned version." >&2
    exit 1
  fi
}

echo "== checking installed tool versions against scripts/tool-versions.sh =="
check_version opa "$(opa version | awk '/^Version:/ {print $2}')" "${OPA_VERSION}"
check_version conftest "$(conftest --version | awk '/^Conftest:/ {print $2}')" "${CONFTEST_VERSION}"
check_version kubeconform "$(kubeconform -v | sed 's/^v//')" "${KUBECONFORM_VERSION}"

echo "== kubeconform (structural schema validation) =="
kubeconform -summary -strict \
  -kubernetes-version "${KUBECONFORM_TARGET_K8S_VERSION}" \
  -schema-location "https://raw.githubusercontent.com/yannh/kubernetes-json-schema/${KUBECONFORM_SCHEMA_COMMIT}/{{.NormalizedKubernetesVersion}}-standalone{{.StrictSuffix}}/{{.ResourceKind}}{{.KindSuffix}}.json" \
  examples/pass examples/fail examples/reference

echo "== opa fmt check =="
opa fmt --fail policy/ -d

echo "== opa check --strict =="
opa check --strict policy/

echo "== opa test, with production-file coverage gate =="
opa test policy/ -v
coverage_json="$(mktemp)"
trap 'rm -f "$coverage_json"' EXIT
opa test policy/ --coverage --format json > "$coverage_json"
python3 -c "
import json
d = json.load(open('$coverage_json'))
# The blended top-level 'coverage' field includes test files in the
# denominator, and a test file is ~100% covered by definition just by
# running - that blend is what let common.rego's real 68.97% hide behind
# an overall 96.95% before the CronJob init-container gap in that file
# got found and fixed. Measuring production files only is the honest
# version of this gate.
covered = sum(c.get('covered_lines', 0) for f, c in d['files'].items() if not f.endswith('_test.rego'))
total = sum(c.get('covered_lines', 0) + c.get('not_covered_lines', 0) for f, c in d['files'].items() if not f.endswith('_test.rego'))
pct = 100 * covered / total if total else 100
print(f'production-file coverage: {pct:.2f}% ({covered}/{total})')
assert pct >= 95, f'production-file coverage {pct:.2f}% is below the 95% threshold'
"

echo "== exact per-policy fixture coverage, including completeness =="
python3 scripts/assert_policy_coverage.py \
  --policy-dir policy \
  --fail-dir examples/fail \
  --map examples/fail/privileged.yaml=policies.privileged \
  --map examples/fail/privilege-escalation.yaml=policies.privilege_escalation \
  --map examples/fail/host-namespaces.yaml=policies.host_namespaces \
  --map examples/fail/non-root.yaml=policies.non_root \
  --map examples/fail/resource-limits.yaml=policies.resource_limits \
  --map examples/fail/static-gcp-key.yaml=policies.static_gcp_key \
  --map examples/fail/malformed-workload-identity-annotation.yaml=policies.static_gcp_key \
  --map examples/fail/list-input.yaml=policies.reject_list_input \
  --pass-glob 'examples/pass/**/*.yaml' \
  --pass-glob 'examples/pass/**/*.yml'

echo "== all gates passed =="

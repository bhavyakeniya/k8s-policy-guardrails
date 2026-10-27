#!/usr/bin/env bash
# The single entry point for every gate this repo enforces - CI calls
# exactly this script, so "it passed locally" and "it passed in CI" mean
# the same thing. Before this existed, the README's quick start only ran
# `opa test`, which is a small fraction of what CI actually checks
# (kubeconform, opa fmt, opa check --strict, the coverage threshold, the
# exact-fixture assertion) - confirmed directly by diffing the two.
# Requires opa, conftest, and kubeconform on PATH (see README Prerequisites).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

KUBECONFORM_TARGET_K8S_VERSION="${KUBECONFORM_TARGET_K8S_VERSION:-1.37.1}"
KUBECONFORM_SCHEMA_COMMIT="${KUBECONFORM_SCHEMA_COMMIT:-f7d855e49c34b039c9ef2196444910275e31e09e}"

echo "== kubeconform (structural schema validation) =="
kubeconform -summary -strict \
  -kubernetes-version "${KUBECONFORM_TARGET_K8S_VERSION}" \
  -schema-location "https://raw.githubusercontent.com/yannh/kubernetes-json-schema/${KUBECONFORM_SCHEMA_COMMIT}/{{.NormalizedKubernetesVersion}}-standalone{{.StrictSuffix}}/{{.ResourceKind}}{{.KindSuffix}}.json" \
  examples/pass examples/fail

echo "== opa fmt check =="
opa fmt --fail policy/ -d

echo "== opa check --strict =="
opa check --strict policy/

echo "== opa test, with production-file coverage gate =="
opa test policy/ -v
opa test policy/ --coverage --format json > /tmp/opa-coverage.json
python3 -c "
import json
d = json.load(open('/tmp/opa-coverage.json'))
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
rm -f /tmp/opa-coverage.json

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

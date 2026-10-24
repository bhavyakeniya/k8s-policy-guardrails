# k8s-policy-guardrails

[![policy-ci](https://github.com/bhavyakeniya/k8s-policy-guardrails/actions/workflows/ci.yml/badge.svg)](https://github.com/bhavyakeniya/k8s-policy-guardrails/actions/workflows/ci.yml)

Policy-as-code guardrails for Kubernetes manifests, written in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/)
and enforced with [Open Policy Agent](https://www.openpolicyagent.org/) / [conftest](https://www.conftest.dev/).
Every policy ships with unit tests and its own isolated fail fixture, asserted against
the exact policy namespace it must trip - not just "the gate failed somehow" - and a
GitHub Actions workflow runs all of it on every push to `main` and every pull request.

This is a from-scratch demo repo, not a copy of any employer's codebase. The patterns
(admission-style guardrails, static-key detection instead of proving Workload
Identity, a CI gate that runs security checks before merge) mirror real
platform-engineering work I've shipped, reimplemented here generically with synthetic
manifests.

This repo has been through several rounds of external review; see
[`docs/review-history.md`](docs/review-history.md) for the detailed, reproduced-before-fixed
record. This README states only the resulting current behavior.

## What it checks

| Policy | File | Standard |
|---|---|---|
| Deny privileged containers | `policy/deny_privileged.rego` | CIS Kubernetes Benchmark, Pod Security Policies section |
| Deny `allowPrivilegeEscalation` (Linux pods only) | `policy/deny_privilege_escalation.rego` | CIS Kubernetes Benchmark, Pod Security Policies section |
| Deny `hostNetwork` / `hostPID` / `hostIPC` | `policy/deny_host_namespaces.rego` | CIS Kubernetes Benchmark, Pod Security Policies section |
| Require non-root containers, including cross-checking `runAsUser: 0` against `runAsNonRoot` at both pod and container level | `policy/require_non_root.rego` | CIS Kubernetes Benchmark, Pod Security Policies section |
| Require positive, syntactically valid Kubernetes Quantity CPU/memory limits (regular/init containers only) | `policy/require_resource_limits.rego` | Kubernetes security checklist (resource-management guidance) |
| Workload Identity annotation format (not full wiring) | `policy/deny_static_gcp_key.rego` | CIS Google Cloud Platform Benchmark (service-account key hygiene) |
| Reject collection-shaped input (`List`, `PodList`, `DeploymentList`, ...) | `policy/reject_list_input.rego` | Internal guardrail - no external standard |

CIS control numbers are intentionally not cited - see review history for why.
"Standard" above describes the section a check is inspired by, not a pinned, numbered
control mapping.

## Supported input shapes

`policy/common_test.rego` tests this matrix directly against the shared helpers, not
indirectly through whichever shape an individual policy's test happens to use.

| Kind | Regular containers | Init containers | Ephemeral containers |
|---|---|---|---|
| Pod | ✅ | ✅ | ✅ (security checks only, never resource limits) |
| Deployment / StatefulSet / DaemonSet / Job / CronJob | ✅ | ✅ | not supported - Kubernetes only adds ephemeral containers to an already-running Pod via a subresource |
| `List`, `PodList`, `DeploymentList`, any `*List` with `items` | **rejected outright** | | |

`allowPrivilegeEscalation` is additionally skipped for any shape above when
`spec.os.name: windows` is set.

## Known limitations

- **Collection-shaped input is rejected, not inspected.** Submit individual manifests,
  or multi-document YAML (`---` separated), instead.
- **The static-key secret-volume check matches on the Secret's name**, not its actual
  contents. A Secret named e.g. `db-creds` that still held a GCP key would slip past
  it.
- **The Workload Identity annotation check cannot prove Workload Identity is actually
  configured end-to-end** - it validates annotation format only.
- **There is currently no exception mechanism** - governed or otherwise.
- **These policies assume schema-valid input.** CI enforces that with `kubeconform
  -strict` against every example manifest, pinned to an exact Kubernetes version and
  an immutable schema-repo commit (kubeconform's defaults - `-kubernetes-version
  master` and its schema repo's `master` branch - are both moving targets, confirmed
  against kubeconform's own docs). A user running `conftest` directly against a
  hand-edited manifest that skips that step is on their own for structural validity.
- **CPU/memory limits are validated as positive and syntactically well-formed, not
  full Kubernetes semantics.** `cpu: "0.0005"` is finer than Kubernetes' documented
  1m/0.001 CPU precision floor, and passes both this check and kubeconform - confirmed
  directly. Server-side CPU-precision semantics are out of scope here.

## Architecture

Every policy lives in its own package (`policies.privileged`, `policies.non_root`,
etc.) instead of one shared `main` package. That keeps each policy's `deny` set
independent, so a unit test for one policy never picks up an unrelated violation from
another policy evaluating the same input. Shared helpers (flattening containers and
pod specs across Pod/Deployment/StatefulSet/DaemonSet/Job/CronJob shapes) live once in
`policy/common.rego` under `package common` and get imported where needed.

## Quick start

```bash
brew install opa conftest

# Run the unit tests for every policy
opa test policy/ -v

# Check a manifest against every policy package
conftest test --all-namespaces path/to/manifest.yaml --policy policy
```

`examples/fail/` holds one isolated fixture per policy; `examples/pass/` holds
manifests that must pass every policy. What CI actually asserts - exact namespace per
fixture, not just a non-zero exit:

```bash
python3 scripts/assert_policy_coverage.py --policy-dir policy --fail-dir examples/fail \
  --map examples/fail/privileged.yaml=policies.privileged \
  --map examples/fail/privilege-escalation.yaml=policies.privilege_escalation \
  --map examples/fail/host-namespaces.yaml=policies.host_namespaces \
  --map examples/fail/non-root.yaml=policies.non_root \
  --map examples/fail/resource-limits.yaml=policies.resource_limits \
  --map examples/fail/static-gcp-key.yaml=policies.static_gcp_key \
  --map examples/fail/malformed-workload-identity-annotation.yaml=policies.static_gcp_key \
  --map examples/fail/list-input.yaml=policies.reject_list_input \
  --pass-glob 'examples/pass/*.yaml'
```

## Project structure

```
policy/
  common.rego                   # package common - shared helpers
  common_test.rego               # the supported-input matrix, tested against the helpers directly
  deny_privileged.rego            # package policies.privileged
  deny_privilege_escalation.rego
  deny_host_namespaces.rego
  require_non_root.rego
  require_resource_limits.rego
  deny_static_gcp_key.rego
  reject_list_input.rego          # package policies.reject_list_input
  *_test.rego                     # opa test unit tests, one file per policy
examples/
  fail/                           # one isolated fixture per policy
  pass/                           # manifests that must pass every policy
scripts/assert_policy_coverage.py # asserts exact namespace per fixture
docs/review-history.md             # detailed record of external review findings
.github/workflows/ci.yml           # fmt/check/test/coverage/exact-fixture gates
```

## CI

`.github/workflows/ci.yml` runs with `permissions: contents: read` and a 10-minute
timeout on a pinned `ubuntu-24.04` runner. It installs checksum-verified OPA,
conftest, and [kubeconform](https://github.com/yannh/kubeconform) binaries and a
SHA-pinned `actions/checkout`, runs `kubeconform -strict` (pinned to an exact
Kubernetes version and an immutable schema-repo commit, not kubeconform's mutable
`master` defaults) against every example manifest for structural schema validation -
it does **not** validate Kubernetes quantity string format, see Known limitations -
runs `opa fmt --fail` and `opa check
--strict`, runs the unit test suite with a 95% coverage gate computed from
production `.rego` files only, then runs `scripts/assert_policy_coverage.py` to
assert each fail fixture trips its own exact policy namespace and each pass fixture
is clean everywhere.

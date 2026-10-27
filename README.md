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
| Require positive, syntactically valid Kubernetes Quantity CPU/memory limits (manifest hygiene, not resource governance - see Known limitations) | `policy/require_resource_limits.rego` | Kubernetes security checklist (resource-management guidance) |
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
- **The resource-limits check is manifest hygiene, not resource governance.** An
  absurd single value (`cpu: "1E"`, `memory: "1Ei"`) passes - confirmed directly - and
  no per-Pod policy can constrain aggregate consumption across replicas or a
  namespace. Kubernetes' own mechanisms for those problems, `LimitRange` and
  `ResourceQuota`, are illustrated (not enforced by this repo) in
  `examples/reference/limitrange-resourcequota.yaml`.
- **`GOOGLE_APPLICATION_CREDENTIALS` is banned outright, not detected as a static
  key.** Confirmed against Google's own ADC docs: this env var can legitimately point
  at a Workload/Workforce Identity Federation config containing no key material at
  all, not only a service-account key - an earlier version of this policy's message
  claimed to have found "a mounted key" regardless, which it can't actually prove
  from the path alone. The policy still denies any use of this env var (file-based
  ADC of any kind is disallowed in favor of GKE's native Workload Identity), but says
  so plainly instead of overclaiming what it detected.

## Architecture

Every policy lives in its own package (`policies.privileged`, `policies.non_root`,
etc.) instead of one shared `main` package. That keeps each policy's `deny` set
independent, so a unit test for one policy never picks up an unrelated violation from
another policy evaluating the same input. Shared helpers (flattening containers and
pod specs across Pod/Deployment/StatefulSet/DaemonSet/Job/CronJob shapes) live once in
`policy/common.rego` under `package common` and get imported where needed.

## Quick start

```bash
brew install opa conftest kubeconform

./scripts/verify.sh
```

`scripts/verify.sh` is the single entry point both local dev and CI use - CI's
workflow calls exactly this script, so "it passed locally" and "it passed in CI" mean
the same thing. An earlier version of this README only told you to run `opa test`,
which is a small fraction of what's actually enforced (kubeconform, `opa fmt`,
`opa check --strict`, the coverage threshold, the exact-fixture assertion) - confirmed
directly by diffing the two before fixing it.

To check a single manifest directly:

```bash
conftest test --all-namespaces path/to/manifest.yaml --policy policy
```

`examples/fail/` holds one isolated fixture per policy; `examples/pass/` holds
manifests that must pass every policy.

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
  reference/                      # illustrative only - not enforced or validated by CI
scripts/
  verify.sh                       # the one entry point local dev and CI both run
  assert_policy_coverage.py       # asserts exact namespace per fixture, and completeness
docs/review-history.md             # detailed record of external review findings
.github/workflows/ci.yml           # installs pinned tools, then calls scripts/verify.sh
```

## CI

`.github/workflows/ci.yml` runs with `permissions: contents: read` and a 10-minute
timeout on a pinned `ubuntu-24.04` runner. It installs checksum-verified OPA,
conftest, and [kubeconform](https://github.com/yannh/kubeconform) binaries and a
SHA-pinned `actions/checkout`, then calls `scripts/verify.sh` - the same script a
local run uses - which runs `kubeconform -strict` (pinned to an exact Kubernetes
version and an immutable schema-repo commit, not kubeconform's mutable `master`
defaults; it does **not** validate Kubernetes quantity string format, see Known
limitations), `opa fmt --fail`, `opa check --strict`, the unit test suite with a 95%
coverage gate computed from production `.rego` files only, and
`scripts/assert_policy_coverage.py` to assert each fail fixture trips its own exact
policy namespace, each pass fixture is clean everywhere, and the fixture-to-policy
mapping itself is complete (every `policies.*` package has a fixture, every fixture
file has a mapping).

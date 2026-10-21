# k8s-policy-guardrails

Policy-as-code guardrails for Kubernetes manifests, written in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/)
and enforced with [Open Policy Agent](https://www.openpolicyagent.org/) / [conftest](https://www.conftest.dev/).
Every policy ships with unit tests and a known-bad / known-good manifest pair, and a
GitHub Actions workflow runs all of it on every push and pull request.

This is a from-scratch demo repo, not a copy of any employer's codebase. The patterns
(admission-style guardrails, Workload Identity enforcement instead of static keys, a
CI gate that runs security checks before merge) mirror real platform-engineering work
I've shipped, reimplemented here generically with synthetic manifests.

## What it checks

| Policy | File | Standard |
|---|---|---|
| Deny privileged containers | `policy/deny_privileged.rego` | CIS Kubernetes Benchmark 5.2.1 |
| Deny `allowPrivilegeEscalation` | `policy/deny_privilege_escalation.rego` | CIS Kubernetes Benchmark 5.2.5 |
| Deny `hostNetwork` / `hostPID` / `hostIPC` | `policy/deny_host_namespaces.rego` | CIS Kubernetes Benchmark 5.2.2 / 5.2.3 / 5.2.4 |
| Require non-root containers | `policy/require_non_root.rego` | CIS Kubernetes Benchmark 5.2.6 |
| Require CPU/memory limits | `policy/require_resource_limits.rego` | Kubernetes Pod Security Standards (resource hygiene) |
| Deny static GCP keys, require Workload Identity | `policy/deny_static_gcp_key.rego` | CIS Google Cloud Platform Benchmark (service-account key hygiene) |

CIS control numbers are quoted from the CIS Kubernetes Benchmark's section 5.2 (Pod
Security Standards); double-check the exact wording against the current benchmark PDF
before citing a specific control number in a compliance context — this repo is a
policy-enforcement demo, not a certified compliance mapping.

## Why a dedicated `policies.*` package per file

Every policy lives in its own package (`policies.privileged`, `policies.non_root`,
etc.) instead of one shared `main` package. That keeps each policy's `deny` set
independent, so a unit test for one policy never picks up an unrelated violation from
another policy evaluating the same input. Shared helpers (flattening containers and
pod specs across Pod/Deployment/StatefulSet/DaemonSet/Job/CronJob shapes) live once in
`policy/common.rego` under `package common` and get imported where needed.

## Usage

```bash
# Run the unit tests for every policy
opa test policy/ -v

# Check a manifest against every policy package
conftest test --all-namespaces path/to/manifest.yaml --policy policy
```

`examples/fail/` holds manifests that should trip the guardrails; `examples/pass/`
holds manifests that should pass cleanly. Both are exercised in CI on every push.

## CI

`.github/workflows/ci.yml` installs pinned OPA and conftest binaries (no third-party
GitHub Actions in the supply chain), runs the unit test suite, then asserts the
known-bad examples fail the gate and the known-good examples pass it.

# k8s-policy-guardrails

[![policy-ci](https://github.com/bhavyakeniya/k8s-policy-guardrails/actions/workflows/ci.yml/badge.svg)](https://github.com/bhavyakeniya/k8s-policy-guardrails/actions/workflows/ci.yml)

Policy-as-code guardrails for Kubernetes manifests, written in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/)
and enforced with [Open Policy Agent](https://www.openpolicyagent.org/) / [conftest](https://www.conftest.dev/).
Every policy ships with unit tests and its own isolated fail fixture, asserted against
the exact policy namespace it must trip (not just "the gate failed somehow"), and a
GitHub Actions workflow runs all of it on every push to `main` and every pull request.

This is a from-scratch demo repo, not a copy of any employer's codebase. The patterns
(admission-style guardrails, static-key detection instead of proving Workload Identity,
a CI gate that runs security checks before merge) mirror real platform-engineering work
I've shipped, reimplemented here generically with synthetic manifests.

## What it checks

| Policy | File | Standard |
|---|---|---|
| Deny privileged containers | `policy/deny_privileged.rego` | CIS Kubernetes Benchmark, Pod Security Policies section |
| Deny `allowPrivilegeEscalation` | `policy/deny_privilege_escalation.rego` | CIS Kubernetes Benchmark, Pod Security Policies section - **Linux-only**, skipped for `spec.os.name: windows`, see note below |
| Deny `hostNetwork` / `hostPID` / `hostIPC` | `policy/deny_host_namespaces.rego` | CIS Kubernetes Benchmark, Pod Security Policies section |
| Require non-root containers | `policy/require_non_root.rego` | CIS Kubernetes Benchmark, Pod Security Policies section |
| Require CPU/memory limits | `policy/require_resource_limits.rego` | Kubernetes security checklist (resource-management guidance) - **not** a Pod Security Standards control, and **not applied to ephemeral containers** (Kubernetes forbids `resources` on them entirely), see notes below |
| Malformed Workload Identity annotation | `policy/deny_static_gcp_key.rego` | CIS Google Cloud Platform Benchmark (service-account key hygiene); does not and cannot prove Workload Identity is fully wired up, see note below |
| Reject collection-shaped input (`List`, `PodList`, `DeploymentList`, ...) | `policy/reject_list_input.rego` | Internal guardrail - no external standard |

Accuracy notes, all added after external reviews caught them - each one was reproduced
directly before being fixed, not just taken on the reviewer's word:

- **Specific CIS control numbers are deliberately not cited.** Two different sources I
  checked gave contradictory section numbers for the same checks across CIS Kubernetes
  Benchmark versions (one maps 5.2.1 to privileged containers, another maps 5.2.1 to an
  unrelated policy-mechanism control), and I have no reliable way to pin one version's
  numbering as definitively current without the paid/registered CIS PDF. Citing a
  specific number I can't verify would be worse than not citing one.
- **Resource limits are not a Pod Security Standards control** - checked against the
  official PSS baseline/restricted profile lists, which cover host namespaces,
  privileged, capabilities, non-root, privilege escalation, seccomp and volume types,
  not resource quotas. An earlier version of this README claimed PSS alignment for
  this policy; that was wrong.
- **The Workload Identity check only validates annotation format, not that Workload
  Identity is actually configured.** It used to deny every ServiceAccount missing the
  annotation entirely, which was wrong on three counts confirmed against GKE's own
  docs: not every ServiceAccount needs GCP access, GKE also supports binding IAM
  directly to a ServiceAccount's principal without this annotation, and even where the
  annotation is the right mechanism, the IAM-side `workloadIdentityUser` binding lives
  in Terraform/gcloud state this policy can never see from a manifest alone. It now
  only denies a *malformed* annotation value, not a missing one.
- **The annotation-format check now implements Google's actual service-account-ID
  grammar** (`[a-z]([-a-z0-9]*[a-z0-9])?`, 6-30 characters, for both the account and
  project components), not just "has an `@` and the right domain suffix and no
  whitespace." The old regex accepted `!!!@???.iam.gserviceaccount.com`; confirmed
  directly before fixing. It deliberately does not accept the legacy default-compute-
  service-account format (`N-compute@developer.gserviceaccount.com`) - Google's own
  guidance recommends a dedicated service account for Workload Identity instead.
- **`name` falls back through `metadata.name` -> `metadata.generateName` -> a constant
  placeholder.** `generateName` without `name` is valid, server-generated-name
  Kubernetes. Confirmed directly: a Pod using `generateName` with `hostNetwork`,
  `privileged`, escalation, and a static credential passed every policy clean (12/12)
  before this fallback existed - every violation message needed `name`, which was
  undefined, which made the whole rule undefined.
- **Collection rejection covers every `*List` kind, not just the bare `List`.**
  Kubernetes has dozens of resource-specific collection kinds (`PodList`,
  `DeploymentList`, `ServiceList`, ...). Confirmed directly: a privileged,
  host-networked Pod wrapped in `kind: PodList` also passed clean under the old
  `input.kind == "List"` check. Now checks `endswith(input.kind, "List")` together
  with an `items` array, so a kind that merely happens to end in "List" without being
  a real collection isn't caught by mistake.
- **Ephemeral containers are excluded from the resource-limits check entirely** -
  Kubernetes forbids a `resources` field on an ephemeral container outright, so
  requiring one would make any manifest with a debug ephemeral container permanently,
  unfixably non-compliant. Confirmed directly: an otherwise fully-hardened Pod failed
  only because its ephemeral debugger lacked `resources.limits`, a field it is not
  allowed to have.
- **`allowPrivilegeEscalation` is skipped for Windows pods.** Confirmed against
  Kubernetes' own docs: the API server rejects a Windows Pod outright if
  `allowPrivilegeEscalation` is set at all, true or false - Windows has no privilege-
  escalation concept to toggle. Requiring it unconditionally made this policy and the
  real API server mutually impossible to satisfy for a legitimate Windows workload.
- **The CI coverage gate was computing expression-region counts, not line counts** -
  `covered`/`not_covered` in OPA's JSON output are arrays of row/col ranges (several
  per line), while `covered_lines`/`not_covered_lines` are the actual integer counts.
  `len()` on the wrong arrays reported 97.18% against a deliberately-broken file where
  the correct figure was 95.70% - confirmed by diffing both calculations side by side.

## Supported input shapes

`policy/common_test.rego` exercises this matrix directly against the shared helpers,
not indirectly through whichever shape an individual policy's test happened to use -
that indirection is exactly how the CronJob gap below went unnoticed.

| Kind | Regular containers | Init containers | Ephemeral containers |
|---|---|---|---|
| Pod | ✅ | ✅ | ✅ (security checks only - never resource limits, see note above) |
| Deployment | ✅ | ✅ | not supported - Kubernetes only adds ephemeral containers to an already-running Pod via a subresource, never through a Deployment's PodTemplateSpec |
| StatefulSet | ✅ | ✅ | not supported, same reason as Deployment |
| DaemonSet | ✅ | ✅ | not supported, same reason as Deployment |
| Job | ✅ | ✅ | not supported, same reason as Deployment |
| CronJob | ✅ | ✅ | not supported, same reason as Deployment |
| `List`, `PodList`, `DeploymentList`, any `*List` with `items` | **rejected outright**, see Known limitations | | |

`allowPrivilegeEscalation` is additionally skipped for any of the above when
`spec.os.name: windows` is set - see the accuracy note above.

## Known limitations

- **Collection-shaped input (`List`, `PodList`, `DeploymentList`, any `kind` ending in
  `List` with an `items` array) is rejected, not inspected.** Every policy here reads
  `input.kind`/`input.spec`/`input.metadata` directly, assuming `input` IS the
  resource - none of them look inside `items[]`, so a privileged Pod wrapped in any
  collection kind silently passed clean before this was caught and fixed (first for
  the bare `List` kind, then again for the resource-specific `*List` kinds the first
  fix missed). Properly supporting collections means rewriting every helper and every
  policy's `input.*` reference to operate over a `documents[]` set instead - a real,
  larger refactor than this repo has done. Rejecting the input outright is the safer
  near-term fix: submit individual manifests, or multi-document YAML (`---`
  separated), which conftest already evaluates correctly per document.
- **The static-key secret-volume check matches on the Secret's name**, not its actual
  contents - this policy only ever sees a Pod/Deployment manifest, not the referenced
  Secret object's data. A Secret named e.g. `db-creds` that still held a GCP key would
  slip past it. Closing that for real needs conftest's `--combine` mode so a policy
  can cross-reference a Secret's own `type`/`data` against every Pod that mounts it.
- **The Workload Identity annotation check cannot prove Workload Identity is actually
  configured end-to-end** - see the note under "What it checks" above. It validates
  annotation format only.
- **There is currently no exception mechanism at all**, governed or otherwise - an
  earlier `policy.guardrails/exempt` label was removed when the Workload Identity
  check was narrowed to only flag malformed annotations (see above), and nothing
  replaced it. A production version of this would need a real exception path - likely
  a governed one with an owner, a reason, and an expiry, reviewed through something
  like CODEOWNERS - rather than either a self-service label or no path at all.

## Why a dedicated `policies.*` package per file

Every policy lives in its own package (`policies.privileged`, `policies.non_root`,
etc.) instead of one shared `main` package. That keeps each policy's `deny` set
independent, so a unit test for one policy never picks up an unrelated violation from
another policy evaluating the same input. Shared helpers (flattening containers and
pod specs across Pod/Deployment/StatefulSet/DaemonSet/Job/CronJob shapes) live once in
`policy/common.rego` under `package common` and get imported where needed.

## Prerequisites

Install the two CLIs this repo uses (macOS via Homebrew shown; Linux/CI installs the
same pinned binaries directly - see `.github/workflows/ci.yml`):

```bash
brew install opa conftest
```

## Usage

```bash
# Run the unit tests for every policy
opa test policy/ -v

# Check a manifest against every policy package
conftest test --all-namespaces path/to/manifest.yaml --policy policy
```

`examples/fail/` holds one isolated fixture per policy - nothing else in the manifest
is wrong, so the fixture maps to exactly one expected policy namespace, not "some
violation fired." `examples/pass/` holds manifests that must pass every policy. Try
them directly:

```bash
# Each file trips exactly its own policy, nothing else
for f in examples/fail/*.yaml; do conftest test --all-namespaces "$f" --policy policy; done

# Expect a clean pass across every file
conftest test --all-namespaces examples/pass/*.yaml --policy policy

# What CI actually asserts: exact namespace per fixture, not just a non-zero exit
python3 scripts/assert_policy_coverage.py --policy-dir policy \
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

Both are also exercised in CI on every push and pull request.

## Project structure

```
policy/
  common.rego                   # package common - shared helpers (all_containers, all_pod_specs)
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
scripts/assert_policy_coverage.py # asserts exact namespace per fixture, not just a non-zero exit
.github/workflows/ci.yml           # fmt/check/test/coverage/exact-fixture gates, see below
```

## CI

`.github/workflows/ci.yml` runs with `permissions: contents: read` and a 10-minute
timeout on a pinned `ubuntu-24.04` runner. It installs checksum-verified OPA and
conftest binaries and a SHA-pinned `actions/checkout`, runs `opa fmt --fail` and
`opa check --strict`, runs the unit test suite with a 95% coverage gate computed from
production `.rego` files only (excluding test files from the denominator - a blended
figure that counts trivially-100%-covered test files hid the real gap in
`common.rego` before this was caught and fixed), then runs
`scripts/assert_policy_coverage.py` to assert each fail fixture trips its own exact
policy namespace and each pass fixture is clean everywhere, checking the process exit
code and conftest's `exceptions` field so a crash can't be mistaken for success.

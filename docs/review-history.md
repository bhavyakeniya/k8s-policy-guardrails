# Review history

This repo went through several rounds of external review after the initial build.
Every finding below was reproduced directly against this code before being accepted
and fixed - none were taken on the reviewer's word alone. This file is the detailed
record; the main [README](../README.md) states only the resulting current behavior.

## CIS control numbers

Specific CIS control numbers are deliberately not cited anywhere in this repo. Two
different sources gave contradictory section numbers for the same checks across CIS
Kubernetes Benchmark versions (one maps 5.2.1 to privileged containers, another maps
5.2.1 to an unrelated policy-mechanism control), and there's no reliable way to pin
one version's numbering as definitively current without the paid/registered CIS PDF.
Citing a specific number that can't be verified would be worse than not citing one.

## Resource limits and Pod Security Standards

An earlier version of this repo claimed `require_resource_limits.rego` aligned with
the Kubernetes Pod Security Standards. Checked against the official PSS
baseline/restricted profile lists: they cover host namespaces, privileged,
capabilities, non-root, privilege escalation, seccomp, and volume types - not
resource quotas. The claim was wrong and has been corrected; the policy now cites the
separate Kubernetes security checklist's resource-management guidance instead.

## Workload Identity: from "require the annotation" to "validate it if present"

The original `deny_static_gcp_key.rego` denied every `ServiceAccount` missing the
`iam.gke.io/gcp-service-account` annotation. This was wrong on three counts, confirmed
against GKE's own docs:

1. Not every `ServiceAccount` needs GCP API access - most don't.
2. GKE also supports binding IAM directly to a `ServiceAccount`'s principal identifier
   without this annotation at all.
3. Even where the annotation is the right mechanism, the annotation alone doesn't
   prove Workload Identity is wired up - the IAM-side `workloadIdentityUser` binding
   on the GCP service account lives in Terraform/gcloud state this policy can never
   see from a Kubernetes manifest alone.

Denying on absence punished every unrelated `ServiceAccount` and forced a self-service
`policy.guardrails/exempt` label with zero governance to work around it. The policy
now only denies a *malformed* annotation value, which is unambiguous regardless of
which Workload Identity pattern is in use. That label mechanism no longer exists
anywhere in this repo - there is currently no exception mechanism at all. A production
version would need a real one: an owner, a reason, an expiry, reviewed through
something like CODEOWNERS, rather than either a self-service label or no path.

## The annotation-format regex accepted garbage

The original regex (`^[^@\s]+@[^@\s]+\.iam\.gserviceaccount\.com$`) only checked for
an `@`, the right domain suffix, and no whitespace. `!!!@???.iam.gserviceaccount.com`
passed it. Fixed by implementing Google's actual service-account-ID grammar
(`[a-z]([-a-z0-9]*[a-z0-9])?`, 6-30 characters, for both the account and project
components). The fix deliberately does not accept the legacy default-compute-service-
account format (`N-compute@developer.gserviceaccount.com`) - Google's own guidance
recommends a dedicated service account for Workload Identity instead, so rejecting
that format is a feature, not a gap. The regression test suite preserves the exact
exploit string plus minimum-length (6), maximum-length (30), overlength (31),
uppercase, and bad-hyphen-placement cases - the original malformed-annotation test
used `"not-an-email"`, which doesn't even contain an `@`, so a regression back to the
old regex would have stayed green against that test alone.

## `common.name` going undefined on `generateName`

`common.name := input.metadata.name` went undefined for any Pod using
`metadata.generateName` instead of `name` - valid, server-generated-name Kubernetes.
Confirmed directly: a `generateName` Pod with `hostNetwork`, `privileged`, privilege
escalation, a static GCP credential, and no resource limits passed every policy clean
(12/12), because every violation message's `sprintf` needed `name` to build, which was
undefined, which made the whole rule undefined. Fixed with a
`name -> generateName -> constant placeholder` fallback. This is the same bug class as
a fix made earlier in the companion [gcp-iam-baseline](https://github.com/bhavyakeniya/gcp-iam-baseline)
repo (a detection rule accidentally depending on a value only needed for display) -
missed here the first time around.

## `kind: List` and resource-specific collection kinds

Every policy in this repo reads `input.kind`/`input.spec`/`input.metadata` directly,
assuming `input` IS the resource. A `kind: List` wrapping other resources in an
`items` array is a single opaque document from conftest's point of view - none of the
policies look inside `items[]`. Confirmed directly in two rounds:

1. A privileged, host-networked Pod wrapped in `kind: List` passed 11/11 before
   `reject_list_input.rego` existed.
2. The same Pod wrapped in `kind: PodList` also passed clean, because the first fix
   only checked `input.kind == "List"` literally - Kubernetes has dozens of
   resource-specific collection kinds (`PodList`, `DeploymentList`, `ServiceList`, ...).

Now checks `endswith(input.kind, "List")` together with an `items` array, tested
against `List`, `PodList`, and `DeploymentList`. Properly supporting collections would
mean rewriting every helper and every policy's `input.*` reference to operate over a
`documents[]` set instead - a real, larger refactor than this repo has done. Rejecting
the input outright is the safer near-term fix: submit individual manifests, or
multi-document YAML (`---` separated), which conftest already evaluates correctly per
document.

## Ephemeral containers: security checks yes, resource limits no, Deployments no

Kubernetes forbids a `resources` field on an ephemeral container entirely - confirmed
against Kubernetes' own ephemeral-container design docs, then directly: an otherwise
fully-hardened Pod failed `require_resource_limits` only because its debug ephemeral
container lacked `resources.limits`, a field it is not allowed to have. Fixed by
splitting the single `all_containers` helper into `security_relevant_containers`
(regular, init, and ephemeral - security-context fields are meaningful on all three)
and `resource_managed_containers` (regular and init only).

Separately, an earlier version of this repo's supported-input matrix claimed Deployment
support for ephemeral containers. Confirmed against Kubernetes' docs: ephemeral
containers can only be added to an already-running Pod through the dedicated
`ephemeralcontainers` subresource, never declared upfront in a Deployment's
PodTemplateSpec at pod-creation time. That claim was removed.

## Zero-valued resource limits

`require_resource_limits.rego` originally checked only whether `resources.limits.cpu`/
`memory` keys existed, truthily. `limits: {cpu: "0", memory: "0"}` is a valid
Kubernetes manifest - validation only rejects negative quantities, and the kubelet
treats a zero limit as effectively unlimited - and it passed the policy clean,
confirmed directly. A Kubernetes resource quantity can express zero in many forms
(`"0"`, `"0m"`, `"0Mi"`, `"0.0"`, `.0Gi`, or a bare unquoted YAML `0` that parses as a
JSON number rather than a string). Fixed by parsing the leading numeric magnitude out
of the value regardless of unit suffix and requiring it to be strictly greater than
zero, rather than special-casing any one string literal.

## `allowPrivilegeEscalation` on Windows pods

Confirmed against Kubernetes' own Pod Security Standards docs: the API server rejects
a Windows Pod outright if `allowPrivilegeEscalation` is set at all, true or false -
Windows has no privilege-escalation concept to toggle. `deny_privilege_escalation.rego`
originally required the field unconditionally, making the policy and the real API
server mutually impossible to satisfy for a legitimate Windows workload. Fixed by
adding `common.is_windows_pod` (checks `spec.os.name == "windows"` across all
supported pod shapes) and skipping the check when true.

## The CI coverage gate was counting expression regions, not lines

`covered`/`not_covered` in OPA's `--coverage --format json` output are arrays of
expression ranges (row/col start and end) - a single line can hold several
expressions, so `len()` on those arrays counts expression regions, not lines.
`covered_lines`/`not_covered_lines` are the actual integer line counts OPA computes.
Confirmed the drift directly by diffing both calculations against the same
deliberately-broken file: the expression-count method reported 97.18%, the correct
line-count method reported 95.70%. Both happened to read 100% before this was found,
because the repo had no uncovered lines at the time - a latent gate bug, not a live
coverage gap, but one that would have silently under-enforced the threshold the moment
a real gap appeared.

## The negative-test pattern could pass for the wrong reason

The original CI used `if conftest test ...; then exit 1; fi` per fail-fixture file.
Any non-zero result - including a crash - looked identical to "the known-bad plan
correctly failed," and a combined fixture tripping several policies at once could mask
one of them silently regressing. `scripts/assert_policy_coverage.py` now parses
conftest's structured JSON output and asserts each fixture trips its *exact* expected
namespace, checks the process exit code against what each fixture should produce, and
checks for an `exceptions` field so a crash producing truncated-but-valid-looking JSON
can't be mistaken for success. A later round found that an empty `--pass-glob` match
(e.g. if every pass fixture were deleted or renamed) let the pass-fixture loop simply
not execute, leaving the gate's prior success state unchanged and exiting 0 - a silent,
vacuous pass. Fixed to fail loudly when the glob matches nothing.

## Coverage, measured honestly

The top-level `coverage` figure OPA reports blends production and test files into one
percentage, and a test file is ~100% covered by definition just by running. That blend
is what let `common.rego`'s real 68.97% line coverage hide behind an overall 96.95%
before the CronJob init-container gap in that specific file was found and fixed. CI now
computes coverage from production `.rego` files only.

## Projected Secret volumes and the sa-key substring false positive

The static-key secret-volume check only looked at `volume.secret.secretName` - the
directly-mounted Secret shape. Kubernetes also supports [projected volumes](https://kubernetes.io/docs/concepts/storage/projected-volumes/),
where a Secret is referenced via `volume.projected.sources[].secret.name` instead.
Confirmed directly: a hardened Pod mounting the exact same `my-gcp-key` Secret through
the projected shape passed every policy clean. Fixed by extracting Secret names from
both volume shapes into one `secret_volume_names` set and applying the naming
heuristic once, rather than duplicating it per shape.

Separately, that naming heuristic used a plain `contains()` substring check, which
means `sa-key` matched inside `tls-rsa-key` (the substring `sa-key` is literally
present inside `rsa-key`). Confirmed directly: an otherwise fully-hardened Pod
mounting an ordinary TLS secret named `tls-rsa-key` was rejected for a reason that had
nothing to do with GCP. Fixed by requiring each pattern to match as its own token,
delimited by the name's start/end or a `-`/`.` (`(^|[-.])pattern([-.]|$)`), applied to
every pattern in the list rather than just the one reported case - `gcp-key` alone
could just as easily mismatch inside an unrelated name like `gcp-keyboard-config`.

## Malformed quantity strings, and kubeconform's actual coverage

`require_resource_limits.rego`'s quantity check extracted only the leading numeric
prefix and ignored whatever followed it, so `"1garbage"`, `"1MiB"` (the real binary
suffix is `Mi`, not `MiB`), and `"1e"` (exponent notation needs digits after the `e`)
all passed as positive quantities. The suggested fix was to run
[kubeconform](https://github.com/yannh/kubeconform) before conftest and document that
these policies assume schema-valid input, rather than reimplementing Kubernetes' full
Quantity parser in Rego. Checked that assumption directly before trusting it:
kubeconform reports `cpu: "1garbage"` as **valid**, because the Kubernetes OpenAPI
schema types `resources.limits.cpu`/`memory` as a plain string with no
format/pattern constraint - the real apiserver only rejects a malformed quantity
string during semantic admission, a step schema validation doesn't perform. So
kubeconform alone would not have closed this gap.

Fixed with `quantity_pattern`, a regex anchored against the *entire* value matching
Kubernetes' actual quantity grammar - a signed number followed by an optional suffix
from the specific binarySI (`Ki`/`Mi`/`Gi`/`Ti`/`Pi`/`Ei`)/decimalSI
(`n`/`u`/`m`/`k`/`M`/`G`/`T`/`P`/`E`)/exponent (`e`/`E` plus a signed integer) set
Kubernetes defines - not a free-form unit. This validates shape and sign; it
deliberately does not attempt unit-conversion arithmetic (turning `"0.5Gi"` into a
byte count), which is the part that would have actually been "reimplementing the
parser." `kubeconform -strict` was still added to CI as a genuinely useful,
complementary layer - it catches wrong types, missing/unknown fields, and bad
apiVersions, none of which the Rego policies attempt - with an explicit note in both
the workflow and the README that it does not cover quantity-string format.

## Overlapping naming patterns produced duplicate violations

`gcp-key.json` matches both the `gcp-key` and `key.json` patterns in
`static_key_name_patterns`, and the original rule structure (iterate secrets, iterate
patterns, deny per match) produced one deny message per matching pattern instead of
one per secret - two identical-intent violations for the same volume. Fixed by
splitting into `suspicious_secret_names`, a set of names (not name/pattern pairs) that
dedupes for free, then one `deny` rule over that set. Regression test asserts
`count(deny) == 1` for `gcp-key.json` specifically.

## kubeconform's unpinned defaults, and CPU precision as an explicit scope boundary

The `kubeconform -strict` CI step added for the quantity-format gap above was itself
unpinned: `-kubernetes-version` defaults to the literal string `"master"`, and the
default `-schema-location` points at the `master` branch of kubeconform's own schema
repository - confirmed directly against kubeconform's own documentation. Both are
moving targets, so the same commit in this repository could start passing or failing
with no change here at all, which undercut the SHA/checksum pinning work done
elsewhere in this CI. Fixed by pinning `-kubernetes-version` to an exact release
(`1.31.14`) and `-schema-location` to an immutable commit SHA of the schema repo
instead of its mutable branch name - re-verified the pinned invocation still validates
every example manifest correctly before committing.

Separately: `cpu: "0.0005"` is finer than Kubernetes' documented 1m/0.001 CPU
precision floor, and passes both `require_resource_limits.rego`'s quantity check and
kubeconform - confirmed directly, neither treats it as invalid. Investigated whether
Kubernetes hard-rejects this at admission or silently truncates it internally via
apimachinery's millivalue representation; the available sources disagreed enough that
citing a specific rejection mechanism with confidence wasn't possible. Rather than
guess at implementing CPU-specific semantic enforcement on an uncertain premise, this
is documented as an explicit, deliberate scope boundary instead, with a test locking
in the current (accepted) behavior: this policy validates that a quantity is positive
and syntactically well-formed, not full Kubernetes CPU semantics.

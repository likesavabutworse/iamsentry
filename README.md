# iamsentry

A CLI that scans rendered IAM policy documents — raw IAM policy JSON, or ACK
`iam.services.k8s.aws` `Role`/`Policy` CRDs against two independent,
separately-toggleable check layers:

1. **AWS IAM Access Analyzer** (`ValidatePolicy`) -- live AWS API calls, on by
   default.
2. **A local Rego rule engine** -- best-practices and custom rules, no AWS
   dependency.

Findings from both layers are rendered together, grouped by severity, with a
configurable exit-code threshold for CI use.

## Why this exists

AWS's IAM Access Analyzer already does deeper semantic policy validation than
most standalone linters (action/resource correctness, missing conditions,
privilege-escalation warnings) — but it only ships as a raw API. Meanwhile
teams that self-serve IAM roles through GitOps (e.g. the
[aws-controllers-k8s](https://aws-controllers-k8s.github.io/community/) IAM
controller) end up with two disconnected checks: a lint on the *declared*
permissions before merge, and a a permission boundary enforced at apply time —
with nothing in between that scans the roles holistically against a shared,
extensible set of best practices. `iamsentry` aims to fill that gap: it works
out of the box on ACK-managed IAM as a quality-of-life win, but its primary
input is plain IAM policy JSON so it works with any pipeline (Helm, Kustomize,
hand-written, or something else entirely).

### A gap Helm/kubectl/ArgoCD structurally can't see

The ACK IAM CRDs (`Role.spec.inlinePolicies`,
`Role.spec.assumeRolePolicyDocument`, `Policy.spec.policyDocument`) are all
plain `string` fields in the CRD's schema. Helm rendering, `helm lint`, and the
Kubernetes API server's own schema validation on `kubectl apply` only check for
valid string. None of them look *inside* it. A malformed or invalid policy can
make it all the way through and only fail when the ACK controller actually
calls `PutRolePolicy`/`CreateRole` and AWS rejects it -- a runtime reconcile
failure, not a CI-time PR check.

`iamsentry` catches this at two different points:

| Failure class | Caught by | AWS needed? | What Helm/kubectl/ArgoCD see |
|---|---|---|---|
| Malformed JSON (trailing comma, unclosed brace, etc.) | `input.Scan`'s own parser — a hard error, not a soft finding | No | Nothing — it's "a string," schema-valid |
| Syntactically valid JSON, invalid/dangerous IAM grammar (missing `Resource`, a bad action name, etc.) | Access Analyzer `ValidatePolicy` | Yes | Nothing — same reason |
| Structurally valid but insecure (privesc actions, wildcards, etc.) | The Rego layer | No | Nothing |

## Usage

```
iamsentry scan [flags] <file-or-directory>

  -no-aws            disable the AWS Access Analyzer layer (local Rego checks only)
  -rules-dir dir     directory of additional user-supplied .rego rules
  -fail-on level     minimum severity that causes a non-zero exit (default LOW)
  -no-color          disable ANSI color in output
  -suppressions path path to a suppressions YAML file (default: .iamsentry-suppressions.yaml if present)
  -ignore ids        comma-separated rule_ids to ignore for this run (unscoped, unreasoned, not for committing)
  -deny-list path    path to a CheckAccessNotGranted deny-list YAML file (no default; off unless given)
  -deny-list-dir dir directory of deny-list YAML files, merged (mutually exclusive with -deny-list)
```

`iamsentry` never renders Helm charts, Kustomize overlays, or anything else
itself — it consumes already-rendered output. Typical CI usage:

```sh
helm template ./chart -f values/prod.yaml > /tmp/rendered.yaml
iamsentry scan --rules-dir ./iam-rules /tmp/rendered.yaml
```

or, for plain policy JSON produced by any other tool:

```sh
iamsentry scan ./policies/
```

## What it scans

- **Raw IAM policy JSON** (`{"Version": ..., "Statement": [...]}`) — the
  universal input, works regardless of what produced it.
- **ACK `kind: Role`** and **`kind: Policy`** (`iam.services.k8s.aws`) —
  auto-detected in YAML or JSON, single file or a directory scanned
  recursively, multi-document YAML supported.

**Not attempted:** resolving `permissionsBoundary`/`permissionsBoundaryRef`
against the boundary's actual document. IAM permission boundaries are not
statically validated against a role's declared policy at
`CreateRole`/`PutRolePolicy` time — AWS computes the boundary ∩ policy
intersection only at request-authorization time, per API call. A role
policy that exceeds its boundary is not a security hole (the boundary still
caps it); at worst it's a misleading/dead grant in the declared policy. That
class of finding is better served by
[`iam-policy-autopilot`](https://github.com/awslabs/iam-policy-autopilot)
(AWS Labs), which determines what a role's declared permissions actually
correspond to by analyzing the application's source code — the two tools
are complementary.

## AWS Access Analyzer layer

All four Access Analyzer policy-check operations
(`ValidatePolicy`, `CheckAccessNotGranted`, `CheckNoNewAccess`,
`CheckNoPublicAccess`) are **live AWS API calls** requiring an authenticated
session with the matching `access-analyzer:<Operation>` IAM permission.

## Local Rego layer

Built on the embedded [Open Policy Agent](https://www.openpolicyagent.org/) Go
library. Every rule module declares `package iamsentry.rules` and contributes
to a `deny` set; each `deny` entry is an object with `rule_id`, `msg`, and
optional `severity` (`critical`/`high`/`medium`/`low`/`info`, defaults to
`medium`).

**Built-in rule bundle** (`internal/rules/builtin/`) ships six rules,
deliberately narrow and cross-checked against existing prior art rather
than invented ad hoc — see `internal/rules/builtin/README.md` for the full
list and each `.rego` file's header comment for its specific source(s)
(AWS's own `ValidatePolicy` issue codes, Checkov, Trivy, Salesforce's
cloudsplaining/policy_sentry, DataDog's pathfinding.cloud
privilege-escalation dataset):

- Privilege-escalation actions (`iam:PutRolePolicy`, `iam:AttachRolePolicy`,
  etc.) in a role's own policy
- `iam:PassRole` on a wildcard resource with no `Condition`
- A full-admin statement (`Action: "*"`, `Resource: "*"`)
- `iam:*` granted alone
- IAM identity/credential-bootstrapping actions (`iam:CreateUser`,
  `iam:CreateAccessKey`, `iam:CreateSAMLProvider`, etc.) that no
  application/workload role has a legitimate reason to hold
- A resource-scopable action (a small, deliberately conservative allowlist —
  see the file's header for why) granted on a bare `Resource: "*"`, not a
  scoped ARN glob

`rules/examples/` has two worked examples of custom rules:

- `required_owner_tag.rego` — every `Role` must carry an `owner` tag whose
  value is in an allow-list.
- `s3_list_separate_statement.rego` — `s3:ListBucket` (a bucket-level
  action) must not share a statement with object-level actions like
  `s3:GetObject`/`PutObject`, since one `Resource` value can't correctly
  scope both.

## Suppressing findings

Three mechanisms, in the order they're applied, all matching on the
finding's `RuleID` (a rego `rule_id`, or an Access Analyzer `IssueCode` —
falling back to the operation name for the three custom checks, which carry
no issue code):

1. **A suppressions file** — `.iamsentry-suppressions.yaml` in the current
   directory by default, or `--suppressions <path>`. See
   `.iamsentry-suppressions.example.yaml` for the format. Every entry
   requires `rule_id` and `reason`; `source_file` (a glob) and
   `object_name` narrow the match. This is the primary mechanism — it's the
   only one that works for raw IAM JSON input, which has no comment syntax
   for an inline suppression, and it's a committed, reviewable file.
2. **A per-object annotation on ACK CRDs** —
   `metadata.annotations["iamsentry.io/suppress"]: "rule-id-1, rule-id-2"`.
   Idiomatic for teams working purely in the ACK ecosystem; always scoped to
   that one object.
3. **`--ignore rule_id[,rule_id...]`** — a blanket, unscoped, unreasoned CLI
   override for local use. Not meant to be committed.

Suppressed findings are counted (not silently dropped from view) — a
`suppressed N finding(s)` line goes to stderr on every run that suppresses
something.

## CheckAccessNotGranted deny list

`--deny-list <file>` or `--deny-list-dir <dir>` (mutually exclusive) checks
every scanned policy against a deny list — "does this policy grant any of
*these specific* forbidden actions/resources?" — via live AWS
`CheckAccessNotGranted` calls. **Off by default, no built-in list**: unlike the
Rego rules, what's forbidden is an org policy decision, not a universal best
practice, so there's no sensible default. `denylist/examples/example.yaml` is a
an example template covering all three `Access` types.

Each entry needs `id` (becomes the finding's `rule_id`, for suppression)
and at least one of `actions`/`resources`; `reason` is optional:

```yaml
deny:
  - id: no-bucket-delete-or-repolicy
    actions: ["s3:DeleteBucket", "s3:PutBucketPolicy"]
    reason: "no workload role ever needs to delete a bucket or rewrite its bucket policy"
```

**Cost**: `ValidatePolicy` is free, but `CheckAccessNotGranted` (along with
`CheckNoNewAccess` and `CheckNoPublicAccess`) is a billed "custom policy check"
at $0.0020 per API call. Each deny-list entry is one such call per scanned
policy document. A deny list with N entries scanning M policy documents is N×M
billed calls per run. Check
[AWS's pricing page](https://aws.amazon.com/iam/access-analyzer/pricing/) for
the current rate before running this at scale.

## Future extensions

- **`CheckNoNewAccess`** — diffs a new policy against a baseline (e.g. a
  PR's target-branch version) and fails if it grants anything new.
  Implemented and unit-tested, not wired into the CLI yet.
- **`CheckNoPublicAccess`** — checks whether a *resource-based* policy
  (S3 bucket policy, KMS key policy, etc.) allows public access. Implemented
  and unit-tested, not wired in: it doesn't fit this tool's input model well
  today, since `iamsentry` scans IAM roles/policies, not the resource
  policies this operation is built for.
- **Cedar policy language support.**

## Development

```sh
make          # fmt-check, vet, test, build -> bin/iamsentry
make build    # just build -> bin/iamsentry
make test     # go test ./...
make vet      # go vet ./...
make fmt      # gofmt -w .
make clean    # remove bin/
```

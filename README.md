# iamsentry

A CLI that scans rendered IAM policy documents (raw IAM policy JSON, or ACK
`iam.services.k8s.aws` `Role`/`Policy` CRDs) against two independent,
separately-toggleable check layers:

1. **AWS IAM Access Analyzer** (`ValidatePolicy`): live AWS API calls, on by
   default.
2. **A local Rego rule engine**: best-practices and custom rules, no AWS
   dependency.

Findings from both layers are rendered together, grouped by severity, with a
configurable exit-code threshold for CI use.

## Why this exists

AWS's IAM Access Analyzer already does deeper semantic policy validation than
most standalone linters (action/resource correctness, missing conditions,
privilege-escalation warnings), but it only ships as a raw API. Meanwhile
teams that self-serve IAM roles through GitOps (e.g. the
[aws-controllers-k8s](https://aws-controllers-k8s.github.io/community/) IAM
controller) end up with two disconnected checks: a lint on the *declared*
permissions before merge, and a permission boundary enforced at apply time,
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
calls `PutRolePolicy`/`CreateRole` and AWS rejects it: too late for any
CI-time PR check to catch.

`iamsentry` catches this at two different points:

| Failure class | Caught by | AWS needed? | What Helm/kubectl/ArgoCD see |
|---|---|---|---|
| Malformed JSON (trailing comma, unclosed brace, etc.) | `input.Scan`'s own parser; it aborts the scan outright | No | Nothing: it's "a string," schema-valid |
| Syntactically valid JSON, invalid/dangerous IAM grammar (missing `Resource`, a bad action name, etc.) | Access Analyzer `ValidatePolicy` | Yes | Nothing (same reason) |
| Structurally valid but insecure (privesc actions, wildcards, etc.) | The Rego layer | No | Nothing |

## Usage

```
iamsentry scan [flags] <file-or-directory>

  -no-aws            disable the AWS Access Analyzer layer (local Rego checks only)
  -rules-dir dir     directory of additional user-supplied .rego rules
  -fail-on level     minimum severity that causes a non-zero exit, or "never" to always exit 0 (default LOW)
  -no-color          disable ANSI color in output
  -o, -output fmt[=file]  output format[=file]: text (default), sarif, or github (Actions
                      annotations); repeatable, at most one without a file (goes to stdout)
  -suppressions path path to a suppressions YAML file (default: .iamsentry-suppressions.yaml if present)
  -ignore ids        comma-separated rule_ids to ignore for this run (unscoped, unreasoned, local use only)
  -deny-list path    path to a CheckAccessNotGranted deny-list YAML file (no default; off unless given)
  -deny-list-dir dir directory of deny-list YAML files, merged (mutually exclusive with -deny-list)
```

`iamsentry` never renders Helm charts, Kustomize overlays, or anything else
itself; it consumes already-rendered output. Typical CI usage:

```sh
helm template ./chart -f values/prod.yaml > /tmp/rendered.yaml
iamsentry scan --rules-dir ./iam-rules /tmp/rendered.yaml
```

or, for plain policy JSON produced by any other tool:

```sh
iamsentry scan ./policies/
```

## Output formats

`-o`/`-output` picks how findings are rendered, and where. It's repeatable,
so one run can emit several formats at once, e.g. human-readable text on
stdout for the job log, plus a SARIF file for code scanning upload:

```sh
iamsentry scan ./policies/ -o text -o sarif=iamsentry.sarif
```

Give a format a `=file` to send it there instead of stdout. At most one
output can go to stdout.

- `text` is the default: grouped by severity, `file:line (object)`.
- `sarif` produces SARIF 2.1.0, for GitHub code scanning
  (`github/codeql-action/upload-sarif`) or any other SARIF consumer.
- `github` emits GitHub Actions workflow commands
  (`::error file=...,line=...::`), which GitHub shows as inline annotations
  on the PR diff.

## What it scans

- **Raw IAM policy JSON** (`{"Version": ..., "Statement": [...]}`): the
  universal input, works regardless of what produced it.
- **ACK `kind: Role`** and **`kind: Policy`** (`iam.services.k8s.aws`):
  auto-detected in YAML or JSON, single file or a directory scanned
  recursively, multi-document YAML supported.

**Non goals:**

- Resolving `permissionsBoundary`/`permissionsBoundaryRef` against the
  boundary's actual document. IAM permission boundaries are not statically
  validated against a role's declared policy at
  `CreateRole`/`PutRolePolicy` time. AWS computes the boundary ∩ policy
  intersection only at request-authorization time, per API call. A role
  policy that exceeds its boundary is not a security hole (the boundary
  still caps it); at worst it's a misleading/dead grant in the declared
  policy. That class of finding is better served by
  [`iam-policy-autopilot`](https://github.com/awslabs/iam-policy-autopilot)
  (AWS Labs), which determines what a role's declared permissions actually
  correspond to by analyzing the application's source code. The two
  tools are complementary.
- **Full ACK CRD schema validation.** `iamsentry` parses whatever content
  is actually present in `assumeRolePolicyDocument`, `inlinePolicies`, and
  `policyDocument` and validates the IAM policy JSON *inside* those string
  fields. It does not separately validate the CRD against its full schema.
  Full CRD schema validation (required fields, types) is the Kubernetes API 
  server's and the ACK controller's responsibility. If you want
  that caught at CI time too, e.g. flagging a Role manifest with no
  `spec.assumeRolePolicyDocument` at all, pair it with
  [`manifesto`](https://github.com/likesavabutworse/manifesto). It
  evaluates the whole manifest, not just the embedded policy JSON, so it
  can catch structural gaps like this one:

  ```rego
  # Not an iamsentry rule; this is a manifesto policy (a different tool,
  # different package convention and input shape; see "A note on sharing
  # rules with manifesto" below).
  package manifesto.k8s.ack_role_trust_policy

  deny contains {"msg": msg} if {
      input.apiVersion == "iam.services.k8s.aws/v1alpha1"
      input.kind == "Role"
      not is_string(input.spec.assumeRolePolicyDocument)
      msg := sprintf("Role/%s has no spec.assumeRolePolicyDocument", [input.metadata.name])
  }
  ```
- **Dereferencing attached managed policies.** A Role's
  `spec.policies` ARNs are recorded for visibility but never fetched or
  scanned. Scanning a Role checks its trust policy and inline policies
  only. The managed policies those ARNs point to aren't covered unless they are
  supplied separately as their own scan input.

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
deliberately narrow and cross-checked against existing prior art. 
See `internal/rules/builtin/README.md` for the full list and each `.rego` 
file's header comment for its specific source(s):

- Privilege-escalation actions (`iam:PutRolePolicy`, `iam:AttachRolePolicy`,
  etc.) in a role's own policy
- `iam:PassRole` on a wildcard resource with no `Condition`
- A full-admin statement (`Action: "*"`, `Resource: "*"`)
- `iam:*` granted alone
- IAM identity/credential-bootstrapping actions (`iam:CreateUser`,
  `iam:CreateAccessKey`, `iam:CreateSAMLProvider`, etc.) that no
  application/workload role has a legitimate need for
- A resource-scopable action granted on a bare `Resource: "*"`. 
  See [internal/rules/builtin/iam_wildcard_resource_scopable.rego](internal/rules/builtin/iam_wildcard_resource_scopable.rego)

### Contract for custom rules

What this interface guarantees:

- **Input**: a rule's `input` is always one scanned object at a time. 
  `iamsentry` aims to remain a per resource linter. By iterating over 
  discovered objects one at a time, it avoids turning into astateful 
  graph-analysis tool. 
- **Malformed `deny` entries are a hard failure**. A `deny` entry missing 
  `msg` or `rule_id`, or with either as the wrong type, aborts the whole scan 
  (exit 2) rather than silently dropping part of your policy surface.
- **`severity` is always validated.** Omitting it defaults to
  `medium`. Providing it requires one of `critical`, `error`, `high`,
  `medium`, `low`, `info`, `informational`, `suggestion` (case-insensitive)
  Anything else, including a typo like `critial`, is a hard failure.
- **`rule_id` must be unique across every loaded rule**, built-in and
  every `--rules-dir` module combined. Two rules emitting the same
  `rule_id` with different `msg`/`severity` is a hard failure (exit 2) the
  first time a scanned object triggers both of them. 
- **`rule_id` is a stable identifier**: it's what suppressions (file, 
  CRD annotation, and `--ignore`) match against. Renaming a `rule_id` 
  silently orphans every existing suppression for it. 

## Exit codes & severity

A scan ends in exactly one of three outcomes:

| Exit code | Meaning |
|---|---|
| `0` | Clean. All enabled checks completed, and no unsuppressed finding met `-fail-on`'s threshold. |
| `1` | Findings. All enabled checks completed, but at least one unsuppressed finding met the threshold. |
| `2` | Error / incomplete: a required check could not complete (bad flags, unparseable input, a Rego rule bug, a failed AWS API call) or had to abort for a reason unrelated to what the scan actually found. |

Exit `2` is deliberately kept distinct from exit `1`: an incomplete scan
must never be mistaken for a clean one just because it also produced zero
findings. This covers both configuration mistakes caught before any
scanning starts (an invalid `-fail-on` value) and failures mid-scan.

**`-fail-on <level>`** compares every unsuppressed finding's severity
against `<level>` and exits `1` if any finding is at or above it in the
order `ERROR > HIGH > MEDIUM > LOW > INFO`, so `-fail-on LOW` fails on a
LOW, MEDIUM, HIGH, or ERROR  alike, not just an exact match. 
`-fail-on never` is the onlt exception. It always exits `0` regardless of findings, 
for a scan meant to be informational only. Any value is rejected up 
front with exit `2`.

## Suppressing findings

Three mechanisms, in the order they're applied, all matching on the
finding's `RuleID` (a rego `rule_id`, or an Access Analyzer `IssueCode`,
falling back to the operation name for the three custom checks, which carry
no issue code):

1. A suppressions file, `.iamsentry-suppressions.yaml` in the current
   directory by default or `--suppressions <path>`, is the primary
   mechanism. See `.iamsentry-suppressions.example.yaml` for the format.
   Every entry requires `rule_id` and `reason`; `source_file` (a glob) and
   `object_name` narrow the match. It's the only one that works for raw IAM
   JSON input, which has no comment syntax for an inline suppression, and
   it's a committed, reviewable file.
2. A per-object annotation on ACK CRDs,
   `metadata.annotations["iamsentry.io/suppress"]: "rule-id-1, rule-id-2"`,
   is idiomatic for teams working purely in the ACK ecosystem; it's always
   scoped to that one object.
3. `--ignore rule_id[,rule_id...]` is a blanket, unscoped, unreasoned CLI
   override for local use, not meant to be committed.

Suppressed findings are still counted: a `suppressed N finding(s)` line
goes to stderr on every run that suppresses something.

## CheckAccessNotGranted deny list

`--deny-list <file>` or `--deny-list-dir <dir>` (mutually exclusive) checks
every scanned policy for whether it grants any of *these specific* forbidden
actions/resources, via live AWS `CheckAccessNotGranted` calls. **Off by
default, no built-in list**: the Rego rules encode a universal best
practice, but what's forbidden here is each org's own policy decision, so
there's no sensible default. [`examples/denylist-example.yaml`](examples/denylist-example.yaml)
is an example template covering all three `Access` types.

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

### GitHub Action

The repository is also a composite action:

```yaml
permissions:
  contents: read
  security-events: write   # for the SARIF upload

steps:
  - uses: actions/checkout@v7
  - uses: likesavabutworse/iamsentry@main
    with:
      path: ./policies
```

| Input | Default | |
|---|---|---|
| `path` | `.` | IAM policy JSON, or an ACK Role/Policy CRD file or directory |
| `no-aws` | `false` | disable the AWS Access Analyzer layer (local Rego checks only) |
| `rules-dir` | | directory of additional user-supplied `.rego` rules |
| `suppressions` | | path to a suppressions YAML file (default: `.iamsentry-suppressions.yaml` if present) |
| `deny-list` | | path to a `CheckAccessNotGranted` deny-list YAML file |
| `deny-list-dir` | | directory of deny-list YAML files (mutually exclusive with `deny-list`) |
| `args` | | extra `iamsentry scan` arguments, e.g. `--ignore some-rule-id` |
| `fail-on` | `LOW` | `ERROR`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, or `never` |
| `version` | `latest` | a release such as `v0.0.7`; pin one in CI |
| `upload-sarif` | `true` | needs `security-events: write`, and code scanning enabled on a private repository |
| `annotations` | `false` | also print annotations on the PR diff |

The AWS Access Analyzer layer needs AWS credentials in the job (e.g.
`aws-actions/configure-aws-credentials`) unless `no-aws: "true"` is set.

## Future extensions

- **`CheckNoNewAccess`**: diffs a new policy against a baseline (e.g. a
  PR's target-branch version) and fails if it grants anything new.
  Implemented and unit-tested; the CLI doesn't call it yet.
- **`CheckNoPublicAccess`**: checks whether a *resource-based* policy
  (S3 bucket policy, KMS key policy, etc.) allows public access. Implemented
  and unit-tested, but not wired in: it doesn't fit this tool's input model
  well today, since `iamsentry` scans IAM roles/policies, while this
  operation is built for resource policies.
- **Cedar policy language support.**
- **pre-commit hook**

## Development

```sh
make          # fmt-check, vet, test, build -> bin/iamsentry
make build    # just build -> bin/iamsentry
make test     # go test ./...
make vet      # go vet ./...
make fmt      # gofmt -w .
make clean    # remove bin/
```

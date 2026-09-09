# Built-in rule bundle

Six rules, embedded into the binary via `go:embed` (see `../builtin.go`)
and always active unless suppressed (see the README's "Suppressing
findings" section). Each is deliberately narrow and cross-checked against
existing prior art. See the header comment in each file for its specific source(s):

| File | rule_id | Severity |
|---|---|---|
| `iam_privilege_escalation.rego` | `iamsentry.iam.privilege_escalation_action` | high |
| `iam_passrole_no_condition.rego` | `iamsentry.iam.passrole_wildcard_no_condition` | high |
| `iam_full_admin.rego` | `iamsentry.iam.full_admin_statement` | critical |
| `iam_wildcard_action.rego` | `iamsentry.iam.wildcard_iam_action` | high |
| `iam_unnecessary_identity_management.rego` | `iamsentry.iam.unnecessary_identity_management_action` | high |
| `iam_wildcard_resource_scopable.rego` | `iamsentry.iam.wildcard_resource_on_scopable_action` | medium |

`common.rego` holds the `iamsentry_permission_statements` helper shared
across all six — deliberately namespaced with an `iamsentry_` prefix since
every loaded module (built-in and user `--rules-dir` content) shares one
`iamsentry.rules` package, so a generic helper name here could silently
merge with an identically-named partial set in someone's own rule.

All six apply to a Role's inline policies and a Policy/RawPolicy's
document only.

`iam_wildcard_resource_scopable.rego` is the one most worth reading before
extending: it's an *allowlist* of actions confirmed to support
resource-level scoping, specifically to avoid the false-positive class this
kind of check is notorious for (flagging `Describe*`/`List*`-style actions
that only ever support `Resource: "*"` by AWS's own design). Extend that
allowlist deliberately with a documented need.

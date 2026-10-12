# Example custom rule: s3:ListBucket must not share a statement with
# object-level actions (GetObject/PutObject/...) — ListBucket is a
# bucket-level action that takes a bucket ARN, while the object actions take
# an object ARN. Combining them in one statement is a common source
# of "wildcard resource" confusion since one Resource value can't be
# correct for both.
#
# This is a template, not a built-in — copy it into your own --rules-dir and
# adjust the object-action list for your conventions.
package iamsentry.rules

OBJECT_ACTIONS := {"s3:getobject", "s3:putobject", "s3:deleteobject"}

deny[v] {
	stmt := statements[_]
	# Match case-insensitively, same as every built-in rule (IAM action
	# names aren't case-sensitive) — "S3:ListBucket" must trip this the
	# same as "s3:listbucket".
	lowered := {lower(a) | a := stmt.Action[_]}
	lowered["s3:listbucket"]
	matched := {a | a := stmt.Action[_]; OBJECT_ACTIONS[lower(a)]}
	count(matched) > 0
	v := {
		"rule_id": "example.s3.list_bucket_separate_statement",
		"msg": sprintf("statement %q mixes s3:ListBucket with object-level actions %v — use separate statements", [object.get(stmt, "Sid", "<no Sid>"), matched]),
		"severity": "low",
	}
}

# statements collects every IAM statement reachable from this input object,
# regardless of whether it came from a raw policy document, an ACK Policy, or
# an ACK Role's inline policies.
statements[stmt] {
	stmt := input.document.Statement[_]
}

statements[stmt] {
	stmt := input.inline_policies[_].Statement[_]
}

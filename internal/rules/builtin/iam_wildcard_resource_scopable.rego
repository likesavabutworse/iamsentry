# Flags a statement granting an action that supports resource-level
# scoping (a specific ARN, not just "*") on the literal bare wildcard
# Resource "*". Deliberately conservative on both axes, to avoid Checkov's
# well-documented noise problem on this exact class of check:
#
#  1. Only the literal string "*" counts as "wildcard" — a scoped ARN with
#     a glob segment (e.g. "arn:aws:sqs:us-east-1:123456789012:x-*")
#     is legitimate least-privilege scoping and is Rego set-membership
#     matched, i.e. an exact-value comparison, never a substring/glob
#     check — so it never matches here.
#  2. IAMSENTRY_SCOPABLE_ACTIONS is an ALLOWLIST of actions we are
#     confident support resource-level permissions, not a denylist of
#     actions assumed to need scoping. Most IAM actions in fact only
#     support "*" by AWS's own design (every Describe*/List*-style action,
#     sts:GetCallerIdentity, etc.). Cross-checked against Salesforce's
#     policy_sentry project.
package iamsentry.rules

IAMSENTRY_SCOPABLE_ACTIONS := {
	"s3:getobject",
	"s3:putobject",
	"s3:deleteobject",
	"s3:listbucket",
	"dynamodb:getitem",
	"dynamodb:putitem",
	"dynamodb:updateitem",
	"dynamodb:deleteitem",
	"dynamodb:query",
	"dynamodb:scan",
	"sqs:sendmessage",
	"sqs:receivemessage",
	"sqs:deletemessage",
	"sqs:getqueueattributes",
	"sns:publish",
	"kms:decrypt",
	"kms:encrypt",
	"kms:generatedatakey",
	"secretsmanager:getsecretvalue",
	"secretsmanager:describesecret",
	"lambda:invokefunction",
}

deny[v] {
	stmt := iamsentry_permission_statements[_]
	stmt.Effect == "Allow"
	matched := {a | a := stmt.Action[_]; IAMSENTRY_SCOPABLE_ACTIONS[lower(a)]}
	count(matched) > 0
	resources := {r | r := stmt.Resource[_]}
	resources["*"]
	v := {
		"rule_id": "iamsentry.iam.wildcard_resource_on_scopable_action",
		"msg": sprintf("statement %q grants %v on Resource \"*\", but these actions support scoping to a specific resource ARN — narrow Resource to avoid unnecessarily broad access", [object.get(stmt, "Sid", "<no Sid>"), matched]),
		"severity": "medium",
	}
}

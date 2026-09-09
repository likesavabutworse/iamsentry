# Flags iam:PassRole granted on any resource ("*") with no Condition at
# all. AWS's own ValidatePolicy Security Warnings already cover the
# NotResource/wildcard-in-resource-and-NotAction variants of PassRole misuse
# (see the "Pass role with ..." issue codes) — this rule is deliberately
# narrower and complementary: the plain "Resource: *, no Condition" shape,
# which ValidatePolicy does not flag on its own.
#
# Source: DataDog pathfinding.cloud, category "New PassRole" — pairing a
# broad iam:PassRole with a resource-launch action (ec2:RunInstances,
# lambda:CreateFunction, etc.) is the classic escalation path; restricting
# PassRole to specific role ARNs (or adding an iam:PassedToService
# condition) is the standard mitigation.
package iamsentry.rules

deny[v] {
	stmt := iamsentry_permission_statements[_]
	stmt.Effect == "Allow"
	actions := {lower(a) | a := stmt.Action[_]}
	actions["iam:passrole"]
	resources := {r | r := stmt.Resource[_]}
	resources["*"]
	not stmt.Condition
	v := {
		"rule_id": "iamsentry.iam.passrole_wildcard_no_condition",
		"msg": sprintf("statement %q grants iam:PassRole on Resource \"*\" with no Condition — an actor could pass any role to a service they control; scope Resource to specific role ARNs or add an iam:PassedToService condition", [object.get(stmt, "Sid", "<no Sid>")]),
		"severity": "high",
	}
}

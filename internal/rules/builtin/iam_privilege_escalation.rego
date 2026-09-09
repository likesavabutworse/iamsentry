# Flags a statement that grants an IAM action known to let a principal
# escalate its own access entirely within its own policy — no second hop
# needed ("self-escalation", as opposed to methods that require creating
# credentials for or reaching a second principal).
#
# Source: Rhino Security Labs, "AWS Privilege Escalation Methods and
# Mitigation" (Spencer Gietzen, 2019) —
# https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
# Independently corroborated by Salesforce's cloudsplaining, Bridgecrew's
# Checkov (CKV_AWS_286/CKV_AWS_110, which delegate to cloudsplaining for
# this exact check rather than reimplementing it), and DataDog's
# pathfinding.cloud dataset (paths iam-001, iam-005, iam-007 through
# iam-011, iam-013), all citing the same original research.
package iamsentry.rules

IAMSENTRY_PRIVESC_ACTIONS := {
	"iam:createpolicyversion",
	"iam:putrolepolicy",
	"iam:putuserpolicy",
	"iam:putgrouppolicy",
	"iam:attachuserpolicy",
	"iam:attachrolepolicy",
	"iam:attachgrouppolicy",
	"iam:addusertogroup",
	"iam:createloginprofile",
	"iam:updateloginprofile",
	"iam:updateassumerolepolicy",
	"iam:createaccesskey",
}

deny[v] {
	stmt := iamsentry_permission_statements[_]
	stmt.Effect == "Allow"
	matched := {a | a := stmt.Action[_]; IAMSENTRY_PRIVESC_ACTIONS[lower(a)]}
	count(matched) > 0
	v := {
		"rule_id": "iamsentry.iam.privilege_escalation_action",
		"msg": sprintf("statement %q allows %v — a known IAM self-privilege-escalation action; confirm this principal cannot use it to grant itself broader access", [object.get(stmt, "Sid", "<no Sid>"), matched]),
		"severity": "high",
	}
}

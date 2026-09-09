# Flags a statement granting unrestricted administrative access: Action "*"
# on Resource "*". A trivial structural check, but the single highest-
# confidence, zero-noise finding a static scan can make.
#
# Source: Checkov CKV2_AWS_40 ("Ensure AWS IAM policy does not allow full
# IAM privileges").
package iamsentry.rules

deny[v] {
	stmt := iamsentry_permission_statements[_]
	stmt.Effect == "Allow"
	actions := {lower(a) | a := stmt.Action[_]}
	actions["*"]
	resources := {r | r := stmt.Resource[_]}
	resources["*"]
	v := {
		"rule_id": "iamsentry.iam.full_admin_statement",
		"msg": sprintf("statement %q grants Action \"*\" on Resource \"*\" — unrestricted administrative access", [object.get(stmt, "Sid", "<no Sid>")]),
		"severity": "critical",
	}
}

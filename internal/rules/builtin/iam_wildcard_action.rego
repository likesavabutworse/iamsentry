# Flags iam:* granted alone, even short of full Action "*"/Resource "*"
# admin access (see iam_full_admin.rego for that case). Unrestricted IAM
# management is itself a privilege-escalation vector — a principal holding
# it can create/attach/modify any policy, including its own.
#
# Source: Checkov CKV_AWS_40-style wildcard-action checks.
package iamsentry.rules

deny[v] {
	stmt := iamsentry_permission_statements[_]
	stmt.Effect == "Allow"
	actions := {lower(a) | a := stmt.Action[_]}
	actions["iam:*"]
	v := {
		"rule_id": "iamsentry.iam.wildcard_iam_action",
		"msg": sprintf("statement %q grants iam:* — unrestricted IAM management, itself a privilege-escalation vector", [object.get(stmt, "Sid", "<no Sid>")]),
		"severity": "high",
	}
}

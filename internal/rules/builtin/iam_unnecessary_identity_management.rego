# Flags IAM identity-bootstrapping actions that no application/workload
# role has a legitimate reason to hold — creating a new IAM user, an access
# key, a federation provider, or an MFA device is control-plane/human-admin
# territory, never something a service needs to do its job.
#
# Deliberately distinct from iam_privilege_escalation.rego even though two
# actions overlap (iam:CreateAccessKey, iam:CreateUser's login-profile
# cousin iam:CreateLoginProfile is in the privesc list, not here): that
# rule's rationale is "this specific principal could use it to escalate its
# own access"; this rule's rationale is simpler and broader — "no workload
# role needs this at all, regardless of escalation risk." A statement
# holding iam:CreateAccessKey can legitimately trigger both, for two
# different reasons — that's intentional.
#
# Excludes iam:CreateRole/CreatePolicy/AttachRolePolicy-style actions on
# purpose: those are legitimately needed by control-plane roles (e.g. an
# ACK IAM controller)
package iamsentry.rules

IAMSENTRY_UNNECESSARY_IDENTITY_ACTIONS := {
	"iam:createuser",
	"iam:createaccesskey",
	"iam:creategroup",
	"iam:createsamlprovider",
	"iam:createopenidconnectprovider",
	"iam:createvirtualmfadevice",
	"iam:createservicespecificcredential",
}

deny[v] {
	stmt := iamsentry_permission_statements[_]
	stmt.Effect == "Allow"
	matched := {a | a := stmt.Action[_]; IAMSENTRY_UNNECESSARY_IDENTITY_ACTIONS[lower(a)]}
	count(matched) > 0
	v := {
		"rule_id": "iamsentry.iam.unnecessary_identity_management_action",
		"msg": sprintf("statement %q grants %v — IAM identity/credential-bootstrapping actions a workload role has no legitimate need for; if this is genuinely a human-admin or control-plane role, suppress this finding with a documented reason", [object.get(stmt, "Sid", "<no Sid>"), matched]),
		"severity": "high",
	}
}

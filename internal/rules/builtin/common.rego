# Shared helpers for the built-in bundle only. Named with an iamsentry_
# prefix specifically to avoid colliding with a same-named rule in a
# user-supplied --rules-dir module: every module (built-in and user) shares
# one iamsentry.rules package/namespace, so a generic name like `statements`
# here would silently merge with an identically-named partial set in
# user content. See rules/examples/*.rego for the user-facing convention
# (those use a plain `statements` name deliberately, since they're templates
# the user copies and owns outright, not something that ships alongside
# arbitrary third-party rules by default).
package iamsentry.rules

# iamsentry_permission_statements collects every "permissions" statement
# reachable from the scanned object: the single document for a Policy or
# RawPolicy, or every inline policy for a Role. Deliberately excludes a
# Role's trust policy (assume_role_policy) — these rules all look for
# permissions grants, not "who can assume this role."
iamsentry_permission_statements[stmt] {
	stmt := input.document.Statement[_]
}

iamsentry_permission_statements[stmt] {
	stmt := input.inline_policies[_].Statement[_]
}

# Example custom rule: require an "owner" tag with an allowed value.
#
# This is a template, not a built-in — copy it into your own --rules-dir and
# edit ALLOWED_OWNERS for your org. It only applies to kind: Role and
# kind: Policy objects, since raw policy documents (KindRawPolicy) carry no
# tags in IAM's grammar.
package iamsentry.rules

ALLOWED_OWNERS := {"backend", "web"}

deny[v] {
	input.kind == "Role"
	tag_value := object.get(input.tags, "owner", "")
	tag_value == ""
	v := {
		"rule_id": "example.tags.owner_required",
		"msg": sprintf("Role %q has no \"owner\" tag", [input.name]),
		"severity": "medium",
	}
}

deny[v] {
	input.kind == "Role"
	tag_value := object.get(input.tags, "owner", "")
	tag_value != ""
	not ALLOWED_OWNERS[tag_value]
	v := {
		"rule_id": "example.tags.owner_invalid",
		"msg": sprintf("Role %q has owner %q, not one of %v", [input.name, tag_value, ALLOWED_OWNERS]),
		"severity": "medium",
	}
}

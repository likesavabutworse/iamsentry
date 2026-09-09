package rules

import (
	"context"
	"testing"

	"github.com/likesavabutworse/iamsentry/internal/input"
	"github.com/likesavabutworse/iamsentry/internal/policy"
)

func newBuiltinEngine(t *testing.T) (*Engine, context.Context) {
	t.Helper()
	ctx := context.Background()
	sources, err := BuiltinSources()
	if err != nil {
		t.Fatalf("BuiltinSources: %v", err)
	}
	eng, err := NewEngine(ctx, sources, "")
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng, ctx
}

func evalStatement(t *testing.T, eng *Engine, ctx context.Context, stmt policy.Statement) []Violation {
	t.Helper()
	obj := input.Object{
		Kind:     input.KindRawPolicy,
		Document: &policy.Document{Statement: []policy.Statement{stmt}},
	}
	in, err := ToInput(obj)
	if err != nil {
		t.Fatalf("ToInput: %v", err)
	}
	violations, err := eng.Evaluate(ctx, in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return violations
}

func TestBuiltin_PrivilegeEscalationAction(t *testing.T) {
	eng, ctx := newBuiltinEngine(t)

	t.Run("fires on iam:PutRolePolicy", func(t *testing.T) {
		v := evalStatement(t, eng, ctx, policy.Statement{
			Effect:   "Allow",
			Action:   policy.StringOrSlice{"iam:PutRolePolicy"},
			Resource: policy.StringOrSlice{"*"},
		})
		if !hasRule(v, "iamsentry.iam.privilege_escalation_action") {
			t.Errorf("expected the rule to fire, got %v", v)
		}
	})

	t.Run("does not fire on an unrelated action", func(t *testing.T) {
		v := evalStatement(t, eng, ctx, policy.Statement{
			Effect:   "Allow",
			Action:   policy.StringOrSlice{"s3:GetObject"},
			Resource: policy.StringOrSlice{"arn:aws:s3:::bucket/*"},
		})
		if hasRule(v, "iamsentry.iam.privilege_escalation_action") {
			t.Errorf("did not expect the rule to fire, got %v", v)
		}
	})

	t.Run("does not fire on a Deny statement", func(t *testing.T) {
		v := evalStatement(t, eng, ctx, policy.Statement{
			Effect:   "Deny",
			Action:   policy.StringOrSlice{"iam:PutRolePolicy"},
			Resource: policy.StringOrSlice{"*"},
		})
		if hasRule(v, "iamsentry.iam.privilege_escalation_action") {
			t.Errorf("a Deny statement must never fire an Allow-only rule, got %v", v)
		}
	})
}

func TestBuiltin_PassRoleNoCondition(t *testing.T) {
	eng, ctx := newBuiltinEngine(t)

	t.Run("fires on PassRole with wildcard resource and no condition", func(t *testing.T) {
		v := evalStatement(t, eng, ctx, policy.Statement{
			Effect:   "Allow",
			Action:   policy.StringOrSlice{"iam:PassRole"},
			Resource: policy.StringOrSlice{"*"},
		})
		if !hasRule(v, "iamsentry.iam.passrole_wildcard_no_condition") {
			t.Errorf("expected the rule to fire, got %v", v)
		}
	})

	t.Run("does not fire when scoped to a specific role ARN", func(t *testing.T) {
		v := evalStatement(t, eng, ctx, policy.Statement{
			Effect:   "Allow",
			Action:   policy.StringOrSlice{"iam:PassRole"},
			Resource: policy.StringOrSlice{"arn:aws:iam::123456789012:role/my-specific-role"},
		})
		if hasRule(v, "iamsentry.iam.passrole_wildcard_no_condition") {
			t.Errorf("did not expect the rule to fire on a scoped resource, got %v", v)
		}
	})

	t.Run("does not fire when a Condition is present", func(t *testing.T) {
		v := evalStatement(t, eng, ctx, policy.Statement{
			Effect:   "Allow",
			Action:   policy.StringOrSlice{"iam:PassRole"},
			Resource: policy.StringOrSlice{"*"},
			Condition: map[string]any{
				"StringEquals": map[string]any{"iam:PassedToService": "ec2.amazonaws.com"},
			},
		})
		if hasRule(v, "iamsentry.iam.passrole_wildcard_no_condition") {
			t.Errorf("did not expect the rule to fire when a Condition is present, got %v", v)
		}
	})
}

func TestBuiltin_FullAdminStatement(t *testing.T) {
	eng, ctx := newBuiltinEngine(t)

	t.Run("fires on Action * / Resource *", func(t *testing.T) {
		v := evalStatement(t, eng, ctx, policy.Statement{
			Effect:   "Allow",
			Action:   policy.StringOrSlice{"*"},
			Resource: policy.StringOrSlice{"*"},
		})
		if !hasRule(v, "iamsentry.iam.full_admin_statement") {
			t.Errorf("expected the rule to fire, got %v", v)
		}
	})

	t.Run("does not fire when only the action is wildcarded", func(t *testing.T) {
		v := evalStatement(t, eng, ctx, policy.Statement{
			Effect:   "Allow",
			Action:   policy.StringOrSlice{"*"},
			Resource: policy.StringOrSlice{"arn:aws:s3:::bucket/*"},
		})
		if hasRule(v, "iamsentry.iam.full_admin_statement") {
			t.Errorf("did not expect the rule to fire, got %v", v)
		}
	})
}

func TestBuiltin_WildcardIAMAction(t *testing.T) {
	eng, ctx := newBuiltinEngine(t)

	t.Run("fires on iam:*", func(t *testing.T) {
		v := evalStatement(t, eng, ctx, policy.Statement{
			Effect:   "Allow",
			Action:   policy.StringOrSlice{"iam:*"},
			Resource: policy.StringOrSlice{"*"},
		})
		if !hasRule(v, "iamsentry.iam.wildcard_iam_action") {
			t.Errorf("expected the rule to fire, got %v", v)
		}
	})

	t.Run("does not fire on a specific iam action", func(t *testing.T) {
		v := evalStatement(t, eng, ctx, policy.Statement{
			Effect:   "Allow",
			Action:   policy.StringOrSlice{"iam:GetRole"},
			Resource: policy.StringOrSlice{"*"},
		})
		if hasRule(v, "iamsentry.iam.wildcard_iam_action") {
			t.Errorf("did not expect the rule to fire, got %v", v)
		}
	})
}

func TestBuiltin_UnnecessaryIdentityManagementAction(t *testing.T) {
	eng, ctx := newBuiltinEngine(t)

	t.Run("fires on iam:CreateUser", func(t *testing.T) {
		v := evalStatement(t, eng, ctx, policy.Statement{
			Effect:   "Allow",
			Action:   policy.StringOrSlice{"iam:CreateUser"},
			Resource: policy.StringOrSlice{"*"},
		})
		if !hasRule(v, "iamsentry.iam.unnecessary_identity_management_action") {
			t.Errorf("expected the rule to fire, got %v", v)
		}
	})

	t.Run("fires on iam:CreateAccessKey (also, separately, the privesc rule)", func(t *testing.T) {
		v := evalStatement(t, eng, ctx, policy.Statement{
			Effect:   "Allow",
			Action:   policy.StringOrSlice{"iam:CreateAccessKey"},
			Resource: policy.StringOrSlice{"*"},
		})
		if !hasRule(v, "iamsentry.iam.unnecessary_identity_management_action") {
			t.Errorf("expected this rule to fire, got %v", v)
		}
		if !hasRule(v, "iamsentry.iam.privilege_escalation_action") {
			t.Errorf("expected the privesc rule to also fire for a different reason, got %v", v)
		}
	})

	t.Run("does not fire on iam:CreateRole (legitimate for control-plane roles)", func(t *testing.T) {
		v := evalStatement(t, eng, ctx, policy.Statement{
			Effect:   "Allow",
			Action:   policy.StringOrSlice{"iam:CreateRole"},
			Resource: policy.StringOrSlice{"*"},
		})
		if hasRule(v, "iamsentry.iam.unnecessary_identity_management_action") {
			t.Errorf("did not expect the rule to fire on iam:CreateRole, got %v", v)
		}
	})
}

func TestBuiltin_WildcardResourceOnScopableAction(t *testing.T) {
	eng, ctx := newBuiltinEngine(t)

	t.Run("fires on s3:GetObject with bare wildcard resource", func(t *testing.T) {
		v := evalStatement(t, eng, ctx, policy.Statement{
			Effect:   "Allow",
			Action:   policy.StringOrSlice{"s3:GetObject"},
			Resource: policy.StringOrSlice{"*"},
		})
		if !hasRule(v, "iamsentry.iam.wildcard_resource_on_scopable_action") {
			t.Errorf("expected the rule to fire, got %v", v)
		}
	})

	t.Run("does not fire on a scoped ARN with a glob segment", func(t *testing.T) {
		// This is the exact false-positive shape the rule must avoid: a
		// legitimately-scoped resource that merely contains "*" as a
		// glob, not the bare wildcard.
		v := evalStatement(t, eng, ctx, policy.Statement{
			Effect:   "Allow",
			Action:   policy.StringOrSlice{"sqs:SendMessage"},
			Resource: policy.StringOrSlice{"arn:aws:sqs:us-east-1:123456789012:prod-e337a0502b7e4e0794294bf8e966070f-*"},
		})
		if hasRule(v, "iamsentry.iam.wildcard_resource_on_scopable_action") {
			t.Errorf("a scoped ARN glob must not be treated as a bare wildcard, got %v", v)
		}
	})

	t.Run("does not fire on a wildcard-only action not in the allowlist", func(t *testing.T) {
		// s3:ListAllMyBuckets and sts:GetCallerIdentity only ever support
		// Resource "*" by AWS's own design — this is exactly the noise a
		// denylist-shaped version of this rule would produce, and exactly
		// what the allowlist design in iam_wildcard_resource_scopable.rego
		// exists to avoid.
		v := evalStatement(t, eng, ctx, policy.Statement{
			Effect:   "Allow",
			Action:   policy.StringOrSlice{"s3:ListAllMyBuckets", "sts:GetCallerIdentity"},
			Resource: policy.StringOrSlice{"*"},
		})
		if hasRule(v, "iamsentry.iam.wildcard_resource_on_scopable_action") {
			t.Errorf("a wildcard-only action must never fire this rule, got %v", v)
		}
	})
}

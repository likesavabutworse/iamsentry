package rules

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/likesavabutworse/iamsentry/internal/input"
	"github.com/likesavabutworse/iamsentry/internal/policy"
)

func TestBuiltinSourcesLoad(t *testing.T) {
	sources, err := BuiltinSources()
	if err != nil {
		t.Fatalf("BuiltinSources: %v", err)
	}
	if len(sources) == 0 {
		t.Fatal("expected the built-in bundle to contain rule modules")
	}
}

func TestEngine_NoRulesYieldsNoViolations(t *testing.T) {
	ctx := context.Background()
	eng, err := NewEngine(ctx, nil, "")
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	violations, err := eng.Evaluate(ctx, map[string]any{"kind": "RawPolicy"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("expected no violations with zero rules loaded, got %v", violations)
	}
}

func TestEngine_UserSuppliedRule(t *testing.T) {
	dir := t.TempDir()
	rule := `
package iamsentry.rules

deny[v] {
	input.kind == "RawPolicy"
	v := {"rule_id": "test.always_fires", "msg": "test violation", "severity": "high"}
}
`
	if err := os.WriteFile(filepath.Join(dir, "test.rego"), []byte(rule), 0o644); err != nil {
		t.Fatalf("writing rule: %v", err)
	}

	ctx := context.Background()
	eng, err := NewEngine(ctx, nil, dir)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	violations, err := eng.Evaluate(ctx, map[string]any{"kind": "RawPolicy"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %v", violations)
	}
	if violations[0].RuleID != "test.always_fires" || violations[0].Severity != "high" {
		t.Errorf("unexpected violation: %+v", violations[0])
	}

	// A non-matching input must not fire the rule.
	violations, err = eng.Evaluate(ctx, map[string]any{"kind": "Role"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("expected no violations for non-matching input, got %v", violations)
	}
}

func TestEngine_MissingRequiredFieldIsAnError(t *testing.T) {
	dir := t.TempDir()
	rule := `
package iamsentry.rules

deny[v] {
	v := {"msg": "no rule_id here"}
}
`
	if err := os.WriteFile(filepath.Join(dir, "bad.rego"), []byte(rule), 0o644); err != nil {
		t.Fatalf("writing rule: %v", err)
	}

	ctx := context.Background()
	eng, err := NewEngine(ctx, nil, dir)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if _, err := eng.Evaluate(ctx, map[string]any{}); err == nil {
		t.Fatal("expected an error for a deny entry missing rule_id, got nil")
	}
}

// TestExampleRules exercises rules/examples/*.rego against representative
// input, both as a smoke test for the example content and as an end-to-end
// check of the input.Object -> ToInput -> Evaluate path.
func TestExampleRules(t *testing.T) {
	examplesDir := filepath.Join("..", "..", "rules", "examples")
	if _, err := os.Stat(examplesDir); err != nil {
		t.Skipf("rules/examples not found relative to test: %v", err)
	}

	ctx := context.Background()
	eng, err := NewEngine(ctx, nil, examplesDir)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	t.Run("owner tag missing", func(t *testing.T) {
		obj := input.Object{Kind: input.KindRole, Name: "svc-example-prod"}
		in, err := ToInput(obj)
		if err != nil {
			t.Fatalf("ToInput: %v", err)
		}
		violations, err := eng.Evaluate(ctx, in)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if !hasRule(violations, "example.tags.owner_required") {
			t.Errorf("expected example.tags.owner_required to fire, got %v", violations)
		}
	})

	t.Run("owner tag valid", func(t *testing.T) {
		obj := input.Object{Kind: input.KindRole, Name: "svc-example-prod", Tags: map[string]string{"owner": "web"}}
		in, err := ToInput(obj)
		if err != nil {
			t.Fatalf("ToInput: %v", err)
		}
		violations, err := eng.Evaluate(ctx, in)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if hasRule(violations, "example.tags.owner_required") || hasRule(violations, "example.tags.owner_invalid") {
			t.Errorf("valid owner tag should not fire either owner rule, got %v", violations)
		}
	})

	t.Run("s3 list mixed with object actions", func(t *testing.T) {
		obj := input.Object{
			Kind: input.KindRawPolicy,
			Document: &policy.Document{
				Statement: []policy.Statement{{
					Effect:   "Allow",
					Action:   policy.StringOrSlice{"s3:ListBucket", "s3:GetObject"},
					Resource: policy.StringOrSlice{"*"},
				}},
			},
		}
		in, err := ToInput(obj)
		if err != nil {
			t.Fatalf("ToInput: %v", err)
		}
		violations, err := eng.Evaluate(ctx, in)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if !hasRule(violations, "example.s3.list_bucket_separate_statement") {
			t.Errorf("expected example.s3.list_bucket_separate_statement to fire, got %v", violations)
		}
	})

	t.Run("s3 list alone does not fire", func(t *testing.T) {
		obj := input.Object{
			Kind: input.KindRawPolicy,
			Document: &policy.Document{
				Statement: []policy.Statement{{
					Effect:   "Allow",
					Action:   policy.StringOrSlice{"s3:ListBucket"},
					Resource: policy.StringOrSlice{"arn:aws:s3:::bucket"},
				}},
			},
		}
		in, err := ToInput(obj)
		if err != nil {
			t.Fatalf("ToInput: %v", err)
		}
		violations, err := eng.Evaluate(ctx, in)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if hasRule(violations, "example.s3.list_bucket_separate_statement") {
			t.Errorf("s3:ListBucket alone should not fire, got %v", violations)
		}
	})
}

func hasRule(violations []Violation, ruleID string) bool {
	for _, v := range violations {
		if v.RuleID == ruleID {
			return true
		}
	}
	return false
}

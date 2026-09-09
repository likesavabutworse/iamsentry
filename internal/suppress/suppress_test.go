package suppress

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/likesavabutworse/iamsentry/internal/render"
)

func TestLoad_ValidFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "suppressions.yaml")
	content := `
suppressions:
  - rule_id: example.tags.owner_required
    source_file: "testdata/*.yaml"
    reason: "legacy role, ticket JIRA-123 tracks the fix"
  - rule_id: SecurityWarningPassRoleWithStarInResource
    reason: "known false positive, see incident report"
`
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	entries, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].SourceFile != "testdata/*.yaml" {
		t.Errorf("unexpected SourceFile: %q", entries[0].SourceFile)
	}
}

func TestLoad_MissingRuleIDIsRejected(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "suppressions.yaml")
	content := `
suppressions:
  - reason: "no rule_id here"
`
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("writing file: %v", err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected an error for a missing rule_id, got nil")
	}
}

func TestLoad_MissingReasonIsRejected(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "suppressions.yaml")
	content := `
suppressions:
  - rule_id: some.rule
`
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("writing file: %v", err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected an error for a missing reason, got nil")
	}
}

func TestMatch_RuleIDOnly(t *testing.T) {
	set := NewSet([]Entry{{RuleID: "rule.a", Reason: "test"}})
	r := render.Result{RuleID: "rule.a", SourceFile: "any.yaml", ObjectName: "any"}
	if _, ok := set.Match(r); !ok {
		t.Error("expected a match on rule_id alone")
	}
	r2 := render.Result{RuleID: "rule.b"}
	if _, ok := set.Match(r2); ok {
		t.Error("expected no match for a different rule_id")
	}
}

func TestMatch_ScopedToSourceFileGlob(t *testing.T) {
	set := NewSet([]Entry{{RuleID: "rule.a", SourceFile: "roles/*.yaml", Reason: "test"}})

	match := render.Result{RuleID: "rule.a", SourceFile: "roles/svc-a.yaml"}
	if _, ok := set.Match(match); !ok {
		t.Error("expected a match within the glob scope")
	}

	noMatch := render.Result{RuleID: "rule.a", SourceFile: "policies/other.yaml"}
	if _, ok := set.Match(noMatch); ok {
		t.Error("expected no match outside the glob scope")
	}
}

func TestMatch_ScopedToObjectName(t *testing.T) {
	set := NewSet([]Entry{{RuleID: "rule.a", ObjectName: "svc-a", Reason: "test"}})

	if _, ok := set.Match(render.Result{RuleID: "rule.a", ObjectName: "svc-a"}); !ok {
		t.Error("expected a match on the named object")
	}
	if _, ok := set.Match(render.Result{RuleID: "rule.a", ObjectName: "svc-b"}); ok {
		t.Error("expected no match on a different object")
	}
}

func TestApply_SplitsKeptAndSuppressed(t *testing.T) {
	set := NewSet([]Entry{{RuleID: "rule.a", Reason: "test"}})
	results := []render.Result{
		{RuleID: "rule.a", Message: "suppressed"},
		{RuleID: "rule.b", Message: "kept"},
	}
	kept, suppressed := Apply(results, set)
	if len(kept) != 1 || kept[0].Message != "kept" {
		t.Errorf("unexpected kept: %+v", kept)
	}
	if len(suppressed) != 1 || suppressed[0].Message != "suppressed" {
		t.Errorf("unexpected suppressed: %+v", suppressed)
	}
}

func TestFromIgnoreFlag(t *testing.T) {
	entries := FromIgnoreFlag([]string{"rule.a", "", "rule.b"})
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries (empty string skipped), got %d", len(entries))
	}
	for _, e := range entries {
		if e.SourceFile != "" || e.ObjectName != "" {
			t.Errorf("--ignore entries must be unscoped, got %+v", e)
		}
	}
}

func TestFromAnnotation_ScopedToObject(t *testing.T) {
	entries := FromAnnotation([]string{"rule.a"}, "role.yaml", "svc-a")
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.SourceFile != "role.yaml" || e.ObjectName != "svc-a" {
		t.Errorf("annotation entry must be scoped to its object, got %+v", e)
	}

	// A same-named object in a different file must not be suppressed by it.
	set := NewSet(entries)
	other := render.Result{RuleID: "rule.a", SourceFile: "other.yaml", ObjectName: "svc-a"}
	if _, ok := set.Match(other); ok {
		t.Error("annotation suppression leaked across source files")
	}
}

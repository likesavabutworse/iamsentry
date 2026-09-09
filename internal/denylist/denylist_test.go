package denylist

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", p, err)
	}
	return p
}

func TestLoad_ValidFile(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "deny.yaml", `
deny:
  - id: no-bucket-delete
    actions: ["s3:DeleteBucket"]
    reason: "never needed"
  - id: protect-state
    resources: ["arn:aws:s3:::state-bucket/*"]
  - id: no-prod-kms-deletion
    actions: ["kms:ScheduleKeyDeletion"]
    resources: ["arn:aws:kms:*:*:key/prod-*"]
`)
	entries, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[1].Reason != "" {
		t.Errorf("reason should be optional, got %q", entries[1].Reason)
	}
}

func TestLoad_MissingIDIsRejected(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "deny.yaml", `
deny:
  - actions: ["s3:DeleteBucket"]
`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected an error for a missing id, got nil")
	}
}

func TestLoad_MissingActionsAndResourcesIsRejected(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "deny.yaml", `
deny:
  - id: empty-entry
    reason: "nothing to check"
`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected an error for an entry with neither actions nor resources, got nil")
	}
}

func TestLoadDir_MergesFilesAndRejectsDuplicateIDs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.yaml", `
deny:
  - id: rule-a
    actions: ["s3:DeleteBucket"]
`)
	writeFile(t, dir, "b.yaml", `
deny:
  - id: rule-b
    actions: ["iam:CreateUser"]
`)
	entries, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 merged entries, got %d", len(entries))
	}

	writeFile(t, dir, "c.yaml", `
deny:
  - id: rule-a
    actions: ["s3:PutBucketPolicy"]
`)
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("expected an error for a duplicate id across files, got nil")
	}
}

func TestLoad_ExampleFileIsValid(t *testing.T) {
	// denylist/examples/example.yaml is a shipped, documented template —
	// it must always parse and validate cleanly.
	entries, err := Load(filepath.Join("..", "..", "denylist", "examples", "example.yaml"))
	if err != nil {
		t.Fatalf("Load(examples/example.yaml): %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected the example file to contain entries")
	}
}

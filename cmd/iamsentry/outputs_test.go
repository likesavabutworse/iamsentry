package main

import "testing"

func TestParseOutputs_RejectsDuplicatePath(t *testing.T) {
	if _, err := parseOutputs([]string{"sarif=iamsentry.sarif", "text=iamsentry.sarif"}); err == nil {
		t.Fatal("expected an error for two outputs sharing one path, got nil")
	}
}

func TestParseOutputs_AllowsDistinctPaths(t *testing.T) {
	outs, err := parseOutputs([]string{"sarif=out.sarif", "github=out.github"})
	if err != nil {
		t.Fatalf("parseOutputs: %v", err)
	}
	if len(outs) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(outs))
	}
}

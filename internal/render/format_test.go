package render

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestWriteSARIF(t *testing.T) {
	results := []Result{
		{Source: SourceRego, RuleID: "rule.a", Severity: SeverityHigh, Message: "bad", SourceFile: "roles/a.yaml", Line: 12, ObjectName: "svc-a"},
		{Source: SourceAccessAnalyzer, RuleID: "MISSING_RESOURCE", Severity: SeverityInfo, Message: "no line", SourceFile: "p.json", LearnMore: "https://example.com/doc"},
		{Source: SourceRego, RuleID: "rule.a", Severity: SeverityHigh, Message: "bad again", SourceFile: "roles/b.yaml", Line: 3},
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, results); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	run := log.Runs[0]

	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("expected 2 deduplicated rules, got %+v", run.Tool.Driver.Rules)
	}
	if len(run.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(run.Results))
	}
	for _, r := range run.Results {
		if run.Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
			t.Errorf("result %q has ruleIndex %d pointing at rule %q", r.RuleID, r.RuleIndex, run.Tool.Driver.Rules[r.RuleIndex].ID)
		}
	}

	first := run.Results[0] // sorted: HIGH roles/a.yaml first
	if first.Level != "error" || first.Message.Text != "[svc-a] bad" {
		t.Errorf("first result = %+v", first)
	}
	if reg := first.Locations[0].PhysicalLocation.Region; reg == nil || reg.StartLine != 12 {
		t.Errorf("first result region = %+v, want startLine 12", reg)
	}

	last := run.Results[2]
	if last.Level != "note" || last.Locations[0].PhysicalLocation.Region != nil {
		t.Errorf("an INFO result with no line should be a note with no region, got %+v", last)
	}
	if !strings.Contains(buf.String(), `"helpUri": "https://example.com/doc"`) {
		t.Error("LearnMore should become the rule's helpUri")
	}
}

func TestWriteSARIF_NoResultsIsStillValid(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, nil); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	// The SARIF schema requires arrays here; null is invalid.
	if !strings.Contains(buf.String(), `"results": []`) || !strings.Contains(buf.String(), `"rules": []`) {
		t.Errorf("expected an empty results array, got:\n%s", buf.String())
	}
}

func TestWriteGitHub(t *testing.T) {
	results := []Result{
		{Source: SourceRego, RuleID: "rule.a", Severity: SeverityMedium, Message: "50% of, things: bad", SourceFile: "a,b.yaml", Line: 7, LearnMore: "https://x"},
		{Source: SourceAccessAnalyzer, RuleID: "X", Severity: SeverityLow, Message: "m", SourceFile: "p.json"},
	}
	var buf bytes.Buffer
	WriteGitHub(&buf, results)

	want := "::warning file=a%2Cb.yaml,line=7,title=MEDIUM [rego%3Arule.a]::50%25 of, things: bad%0Ahttps://x\n" +
		"::notice file=p.json,title=LOW [access-analyzer%3AX]::m\n"
	if buf.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", buf.String(), want)
	}
}

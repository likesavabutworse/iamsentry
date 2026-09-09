package render

import (
	"testing"

	"github.com/likesavabutworse/iamsentry/internal/awsval"
)

func TestFromAccessAnalyzer_RuleIDPrefersIssueCode(t *testing.T) {
	findings := []awsval.Finding{
		{Check: "ValidatePolicy", IssueCode: "SecurityWarningPassRoleWithStarInResource"},
		{Check: "CheckAccessNotGranted", IssueCode: ""}, // custom checks carry no IssueCode
	}
	results := FromAccessAnalyzer("role.yaml", "svc-a", findings)
	if results[0].RuleID != "SecurityWarningPassRoleWithStarInResource" {
		t.Errorf("RuleID = %q, want the IssueCode", results[0].RuleID)
	}
	if results[1].RuleID != "CheckAccessNotGranted" {
		t.Errorf("RuleID = %q, want fallback to Check when IssueCode is empty", results[1].RuleID)
	}
}

func TestExitCode_ThresholdRespectsSeverityOrder(t *testing.T) {
	results := []Result{{Severity: SeverityLow}}
	if got := ExitCode(results, SeverityHigh); got != 0 {
		t.Errorf("a LOW finding must not fail a HIGH threshold, got exit %d", got)
	}
	if got := ExitCode(results, SeverityLow); got != 1 {
		t.Errorf("a LOW finding must fail a LOW threshold, got exit %d", got)
	}
}

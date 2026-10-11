package render

import (
	"testing"

	"github.com/likesavabutworse/iamsentry/internal/awsval"
	"github.com/likesavabutworse/iamsentry/internal/input"
)

func TestFromAccessAnalyzer_RuleIDPrefersIssueCode(t *testing.T) {
	findings := []awsval.Finding{
		{Check: "ValidatePolicy", IssueCode: "SecurityWarningPassRoleWithStarInResource"},
		{Check: "CheckAccessNotGranted", IssueCode: ""}, // custom checks carry no IssueCode
	}
	results := FromAccessAnalyzer("role.yaml", "svc-a", input.PolicyLocation{}, findings)
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

func TestIsValidThreshold(t *testing.T) {
	for _, s := range []string{"ERROR", "high", "Medium", "LOW", "info", "never", "NEVER"} {
		if !IsValidThreshold(s) {
			t.Errorf("IsValidThreshold(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"MDEIUM", "CRITICAL", "", "none", "off"} {
		if IsValidThreshold(s) {
			t.Errorf("IsValidThreshold(%q) = true, want false", s)
		}
	}
}

func TestExitCode_NeverAlwaysExitsZero(t *testing.T) {
	results := []Result{{Severity: SeverityError}}
	if got := ExitCode(results, "never"); got != 0 {
		t.Errorf("fail-on never must exit 0 even with an ERROR finding, got exit %d", got)
	}
	if got := ExitCode(results, "NEVER"); got != 0 {
		t.Errorf("fail-on never must be case-insensitive, got exit %d", got)
	}
}

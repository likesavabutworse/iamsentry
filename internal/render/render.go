// Package render turns findings from both check layers into scannable
// terminal output and decides the process exit code.
package render

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/likesavabutworse/iamsentry/internal/awsval"
	"github.com/likesavabutworse/iamsentry/internal/rules"
)

// Source distinguishes which layer produced a Result, for grouping/coloring.
type Source string

const (
	SourceAccessAnalyzer Source = "access-analyzer"
	SourceRego           Source = "rego"
)

// Result is the unified shape both layers are normalized into before
// rendering, so the terminal output never special-cases which layer found
// what.
type Result struct {
	Source     Source
	RuleID     string // a rego rule_id, or an Access Analyzer IssueCode — falls back to the operation name (e.g. "CheckAccessNotGranted") when AWS gives no IssueCode. What suppressions match against.
	Severity   string // normalized to one of Severity* below
	Message    string
	SourceFile string
	ObjectName string
	LearnMore  string
}

// Normalized severities, ordered from most to least severe. Every input
// severity string (from either layer) maps into one of these.
const (
	SeverityError  = "ERROR"
	SeverityHigh   = "HIGH"
	SeverityMedium = "MEDIUM"
	SeverityLow    = "LOW"
	SeverityInfo   = "INFO"
)

var severityOrder = map[string]int{
	SeverityError:  0,
	SeverityHigh:   1,
	SeverityMedium: 2,
	SeverityLow:    3,
	SeverityInfo:   4,
}

// NormalizeAccessAnalyzerSeverity maps the two distinct vocabularies the
// four Access Analyzer operations use (ValidatePolicy's FindingType; the
// three custom checks' fixed "FAIL") onto the shared scale.
func NormalizeAccessAnalyzerSeverity(s string) string {
	switch s {
	case "ERROR":
		return SeverityError
	case "SECURITY_WARNING":
		return SeverityHigh
	case "WARNING":
		return SeverityMedium
	case "SUGGESTION":
		return SeverityInfo
	case "FAIL":
		// A custom check (CheckAccessNotGranted/CheckNoNewAccess/
		// CheckNoPublicAccess) failing means AWS could not prove the
		// checked access is absent — treated as high, not error, since
		// unlike ValidatePolicy this isn't a policy-grammar defect.
		return SeverityHigh
	default:
		return SeverityMedium
	}
}

// NormalizeRegoSeverity maps a rule's freeform severity string (rule
// authors write "high"/"medium"/"low"/"info", case-insensitive) onto the
// shared scale. Unrecognized values fall back to medium rather than being
// dropped, so a typo in a custom rule doesn't silently disappear.
func NormalizeRegoSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical", "error":
		return SeverityError
	case "high":
		return SeverityHigh
	case "medium", "":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "info", "informational", "suggestion":
		return SeverityInfo
	default:
		return SeverityMedium
	}
}

// FromAccessAnalyzer converts awsval.Findings for one scanned object into
// unified Results.
func FromAccessAnalyzer(sourceFile, objectName string, findings []awsval.Finding) []Result {
	results := make([]Result, 0, len(findings))
	for _, f := range findings {
		ruleID := f.IssueCode
		if ruleID == "" {
			// The three custom checks (CheckAccessNotGranted/CheckNoNewAccess/
			// CheckNoPublicAccess) carry no IssueCode — fall back to the
			// operation name so RuleID is never empty.
			ruleID = f.Check
		}
		results = append(results, Result{
			Source:     SourceAccessAnalyzer,
			RuleID:     ruleID,
			Severity:   NormalizeAccessAnalyzerSeverity(f.Severity),
			Message:    f.Message,
			SourceFile: sourceFile,
			ObjectName: objectName,
			LearnMore:  f.LearnMore,
		})
	}
	return results
}

// FromRego converts rules.Violations for one scanned object into unified
// Results.
func FromRego(sourceFile, objectName string, violations []rules.Violation) []Result {
	results := make([]Result, 0, len(violations))
	for _, v := range violations {
		results = append(results, Result{
			Source:     SourceRego,
			RuleID:     v.RuleID,
			Severity:   NormalizeRegoSeverity(v.Severity),
			Message:    v.Msg,
			SourceFile: sourceFile,
			ObjectName: objectName,
		})
	}
	return results
}

// Sort orders results by severity (most severe first), then source file,
// for stable, scannable output.
func Sort(results []Result) {
	sort.SliceStable(results, func(i, j int) bool {
		si, sj := severityOrder[results[i].Severity], severityOrder[results[j].Severity]
		if si != sj {
			return si < sj
		}
		return results[i].SourceFile < results[j].SourceFile
	})
}

const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
)

var severityColor = map[string]string{
	SeverityError:  colorRed,
	SeverityHigh:   colorRed,
	SeverityMedium: colorYellow,
	SeverityLow:    colorCyan,
	SeverityInfo:   colorGray,
}

// Write renders results grouped by severity to w. color disables ANSI codes
// when false (e.g. non-terminal CI log output).
func Write(w io.Writer, results []Result, color bool) {
	if len(results) == 0 {
		fmt.Fprintln(w, "No findings.")
		return
	}

	Sort(results)

	var lastSeverity string
	for _, r := range results {
		if r.Severity != lastSeverity {
			fmt.Fprintln(w)
			fmt.Fprintln(w, sevHeading(r.Severity, color))
			lastSeverity = r.Severity
		}
		fmt.Fprint(w, formatResult(r, color))
	}
	fmt.Fprintln(w)
}

func sevHeading(severity string, color bool) string {
	if !color {
		return severity
	}
	return severityColor[severity] + colorBold + severity + colorReset
}

func formatResult(r Result, color bool) string {
	var b strings.Builder
	loc := r.SourceFile
	if r.ObjectName != "" {
		loc = fmt.Sprintf("%s (%s)", loc, r.ObjectName)
	}
	check := fmt.Sprintf("[%s:%s]", r.Source, r.RuleID)
	if color {
		check = colorGray + check + colorReset
	}
	fmt.Fprintf(&b, "  %s %s\n      %s\n", check, loc, r.Message)
	if r.LearnMore != "" {
		fmt.Fprintf(&b, "      %s\n", r.LearnMore)
	}
	return b.String()
}

// ExitCode returns 1 if any Result meets or exceeds threshold, else 0.
// threshold is one of the Severity* constants; an unrecognized threshold is
// treated as SeverityLow (fail on anything but info).
func ExitCode(results []Result, threshold string) int {
	thresholdRank, ok := severityOrder[threshold]
	if !ok {
		thresholdRank = severityOrder[SeverityLow]
	}
	for _, r := range results {
		if rank, ok := severityOrder[r.Severity]; ok && rank <= thresholdRank {
			return 1
		}
	}
	return 0
}

package render

import (
	"fmt"
	"io"
	"strings"
)

// WriteGitHub renders results as GitHub Actions workflow commands
// (::error/::warning/::notice), which GitHub shows as inline annotations
// on the PR diff and in the job summary. No upload step or GitHub Advanced
// Security needed, unlike SARIF.
func WriteGitHub(w io.Writer, results []Result) {
	Sort(results)
	for _, r := range results {
		props := []string{"file=" + escapeGitHubProperty(r.SourceFile)}
		if r.Line > 0 {
			props = append(props, fmt.Sprintf("line=%d", r.Line))
		}
		props = append(props, "title="+escapeGitHubProperty(fmt.Sprintf("%s [%s:%s]", r.Severity, r.Source, r.RuleID)))

		msg := messageWithObject(r)
		if r.LearnMore != "" {
			msg += "\n" + r.LearnMore
		}
		fmt.Fprintf(w, "::%s %s::%s\n", githubLevel(r.Severity), strings.Join(props, ","), escapeGitHubData(msg))
	}
}

func githubLevel(severity string) string {
	switch severity {
	case SeverityError, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	default:
		return "notice"
	}
}

// escapeGitHubData and escapeGitHubProperty follow the escaping rules of
// @actions/core's command.ts: a raw newline would end the command early,
// and a raw ',' or ':' in a property would split it.
func escapeGitHubData(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

func escapeGitHubProperty(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(s)
}

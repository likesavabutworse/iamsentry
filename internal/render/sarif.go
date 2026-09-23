package render

import (
	"encoding/json"
	"io"
	"path/filepath"
)

// SARIF 2.1.0 output, shaped for GitHub code scanning
// (github/codeql-action/upload-sarif) but valid for any SARIF consumer.
// Only the subset of the schema this tool fills is modeled.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string          `json:"id"`
	ShortDescription     sarifText       `json:"shortDescription"`
	HelpURI              string          `json:"helpUri,omitempty"`
	DefaultConfiguration sarifRuleConfig `json:"defaultConfiguration"`
	Properties           sarifRuleProps  `json:"properties"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	Tags []string `json:"tags"`
	// GitHub reads this to show a finding as a security alert with a
	// critical/high/medium/low badge instead of a plain error/warning/note.
	SecuritySeverity string `json:"security-severity,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// sarifLevel maps the shared severity scale onto SARIF's three levels, the
// ones GitHub renders as error/warning/note.
func sarifLevel(severity string) string {
	switch severity {
	case SeverityError, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// securitySeverity maps onto GitHub's CVSS-style bands: >=9.0 critical,
// 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low. INFO gets none, so it stays a
// plain note rather than a security alert.
var securitySeverity = map[string]string{
	SeverityError:  "9.0",
	SeverityHigh:   "7.5",
	SeverityMedium: "5.0",
	SeverityLow:    "3.0",
}

// WriteSARIF renders results as a SARIF 2.1.0 log to w.
func WriteSARIF(w io.Writer, results []Result) error {
	Sort(results)

	rules := []sarifRule{} // SARIF requires an array here, never null
	ruleIndex := map[string]int{}
	sarifResults := make([]sarifResult, 0, len(results))
	for _, r := range results {
		idx, ok := ruleIndex[r.RuleID]
		if !ok {
			idx = len(rules)
			ruleIndex[r.RuleID] = idx
			rules = append(rules, sarifRule{
				ID:                   r.RuleID,
				ShortDescription:     sarifText{Text: r.RuleID},
				HelpURI:              r.LearnMore,
				DefaultConfiguration: sarifRuleConfig{Level: sarifLevel(r.Severity)},
				Properties: sarifRuleProps{
					Tags:             []string{"security", "iam", string(r.Source)},
					SecuritySeverity: securitySeverity[r.Severity],
				},
			})
		}

		loc := sarifPhysicalLocation{ArtifactLocation: sarifArtifact{URI: filepath.ToSlash(r.SourceFile)}}
		if r.Line > 0 {
			loc.Region = &sarifRegion{StartLine: r.Line}
		}
		sarifResults = append(sarifResults, sarifResult{
			RuleID:    r.RuleID,
			RuleIndex: idx,
			Level:     sarifLevel(r.Severity),
			Message:   sarifText{Text: messageWithObject(r)},
			Locations: []sarifLocation{{PhysicalLocation: loc}},
		})
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "iamsentry",
				InformationURI: "https://github.com/likesavabutworse/iamsentry",
				Rules:          rules,
			}},
			Results: sarifResults,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// messageWithObject prefixes the ACK object name, since the file:line alone
// doesn't say which object in a multi-document file a finding is about.
func messageWithObject(r Result) string {
	if r.ObjectName == "" {
		return r.Message
	}
	return "[" + r.ObjectName + "] " + r.Message
}

// Package suppress filters render.Results against suppression entries so a
// known-accepted finding stops failing CI without disabling the rule
// entirely. Three sources feed into one merged Set, in the order the CLI
// applies them: a suppression file (rule_id, optionally scoped to a source
// file glob and/or object name, always with a required reason), per-object
// "iamsentry.io/suppress" annotations on ACK CRDs, and a blanket --ignore
// CLI flag. All three use the same Entry/matching logic.
package suppress

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/likesavabutworse/iamsentry/internal/render"
	"gopkg.in/yaml.v3"
)

// Entry is one suppression. RuleID is required; SourceFile (a
// filepath.Match glob) and ObjectName narrow the match further when set.
// Reason is required for entries loaded from a suppression file (enforced
// by Load, not by this struct, since CLI/annotation-sourced entries are
// exempt — see package doc) but always populated for display.
type Entry struct {
	RuleID     string `yaml:"rule_id"`
	SourceFile string `yaml:"source_file,omitempty"`
	ObjectName string `yaml:"object_name,omitempty"`
	Reason     string `yaml:"reason,omitempty"`
}

type file struct {
	Suppressions []Entry `yaml:"suppressions"`
}

// DefaultFileName is looked for in the current working directory when no
// --suppressions flag is given.
const DefaultFileName = ".iamsentry-suppressions.yaml"

// Load reads and validates a suppression file. Every entry must have a
// rule_id and a reason — the reason requirement is deliberate: a
// suppression file is committed and reviewed, so it must document why.
func Load(path string) ([]Entry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading suppressions file %s: %w", path, err)
	}
	var f file
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("parsing suppressions file %s: %w", path, err)
	}
	for i, e := range f.Suppressions {
		if e.RuleID == "" {
			return nil, fmt.Errorf("%s: suppression #%d has no rule_id", path, i+1)
		}
		if e.Reason == "" {
			return nil, fmt.Errorf("%s: suppression #%d (rule_id: %s) has no reason", path, i+1, e.RuleID)
		}
	}
	return f.Suppressions, nil
}

// FromIgnoreFlag builds unreasoned, unscoped Entries for a blanket --ignore
// rule_id[,rule_id...] CLI override — meant for transient local use, not to
// be committed, so no reason is required.
func FromIgnoreFlag(ruleIDs []string) []Entry {
	entries := make([]Entry, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		if id == "" {
			continue
		}
		entries = append(entries, Entry{RuleID: id, Reason: "--ignore flag"})
	}
	return entries
}

// FromAnnotation builds Entries scoped to exactly one object, for the
// "iamsentry.io/suppress" annotation on an ACK CRD (a comma-separated list
// of rule_ids). sourceFile/objectName pin the match to that object only.
func FromAnnotation(ruleIDs []string, sourceFile, objectName string) []Entry {
	entries := make([]Entry, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		if id == "" {
			continue
		}
		entries = append(entries, Entry{
			RuleID:     id,
			SourceFile: sourceFile,
			ObjectName: objectName,
			Reason:     "iamsentry.io/suppress annotation",
		})
	}
	return entries
}

// Set is a merged, ready-to-apply collection of suppression entries.
type Set struct {
	entries []Entry
}

func NewSet(entries ...[]Entry) Set {
	var s Set
	for _, e := range entries {
		s.entries = append(s.entries, e...)
	}
	return s
}

// Match returns the first Entry that suppresses r, if any.
func (s Set) Match(r render.Result) (Entry, bool) {
	for _, e := range s.entries {
		if e.RuleID != r.RuleID {
			continue
		}
		if e.SourceFile != "" {
			if ok, _ := filepath.Match(e.SourceFile, r.SourceFile); !ok {
				continue
			}
		}
		if e.ObjectName != "" && e.ObjectName != r.ObjectName {
			continue
		}
		return e, true
	}
	return Entry{}, false
}

// Apply splits results into kept and suppressed, in original order.
func Apply(results []render.Result, s Set) (kept []render.Result, suppressed []render.Result) {
	for _, r := range results {
		if _, ok := s.Match(r); ok {
			suppressed = append(suppressed, r)
			continue
		}
		kept = append(kept, r)
	}
	return kept, suppressed
}

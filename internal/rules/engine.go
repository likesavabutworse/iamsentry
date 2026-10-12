// Package rules evaluates scanned policy objects against Rego rule bundles:
// an embedded built-in bundle (see builtin/README.md) and an optional
// user-supplied directory, merged into one evaluation.
//
// Contract: every rule bundle is a Rego package under iamsentry.rules that
// sets a `deny` array. Each element must be an object with at least "msg"
// and "rule_id"; "severity" defaults to "medium" when absent, and must
// otherwise be one of NormalizeSeverity's recognized values — an
// unrecognized severity string is a hard failure, same as a missing msg or
// rule_id, since silently defaulting it could let a finding land under a
// less severe -fail-on bucket than the rule author intended. This package
// makes no assumption about how many rules exist — zero is valid and simply
// yields zero findings. rule_id must be unique across every loaded rule,
// builtin and user-supplied alike — passing opa test in an upstream rules
// repo doesn't guarantee this, since a rule's own tests typically only
// trigger that rule's own condition, so Evaluate checks for collisions
// itself and fails the run if it finds one.
package rules

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/rego"
)

const rootPackage = "iamsentry.rules"

// regoSeverityBuckets is the single source of truth for which raw severity
// strings a deny entry may use (case-insensitive) and which canonical
// bucket each belongs to. Bucket names match render.Severity* exactly
// (render has no way to import this package's constants without a cycle,
// since render already imports rules — it calls NormalizeSeverity instead
// of keeping its own copy of this table).
var regoSeverityBuckets = map[string]string{
	"critical":      "ERROR",
	"error":         "ERROR",
	"high":          "HIGH",
	"medium":        "MEDIUM",
	"low":           "LOW",
	"info":          "INFO",
	"informational": "INFO",
	"suggestion":    "INFO",
}

// NormalizeSeverity maps a rule's freeform severity string onto one of the
// canonical buckets ("ERROR", "HIGH", "MEDIUM", "LOW", "INFO"), or "" if s
// isn't a recognized value.
func NormalizeSeverity(s string) string {
	return regoSeverityBuckets[strings.ToLower(s)]
}

// Violation is one `deny` entry produced by a rule.
type Violation struct {
	RuleID   string `json:"rule_id"`
	Msg      string `json:"msg"`
	Severity string `json:"severity"`
}

// Engine evaluates input documents against a compiled set of Rego modules.
type Engine struct {
	query rego.PreparedEvalQuery
}

// Source is one Rego module to load, named for error messages.
type Source struct {
	Name string
	Body string
}

// NewEngine compiles builtins (typically loaded via BuiltinSources) plus
// whatever Sources are found under userRulesDir (pass "" to skip user rules)
// into a single evaluator.
func NewEngine(ctx context.Context, builtins []Source, userRulesDir string) (*Engine, error) {
	var modules []Source
	modules = append(modules, builtins...)

	if userRulesDir != "" {
		userModules, err := loadRegoDir(userRulesDir)
		if err != nil {
			return nil, fmt.Errorf("loading user rules from %s: %w", userRulesDir, err)
		}
		modules = append(modules, userModules...)
	}

	opts := []func(*rego.Rego){
		rego.Query(fmt.Sprintf("data.%s.deny", rootPackage)),
	}
	for _, m := range modules {
		opts = append(opts, rego.Module(m.Name, m.Body))
	}

	pq, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("compiling rego rules: %w", err)
	}
	return &Engine{query: pq}, nil
}

// Evaluate runs every loaded rule against input (typically an
// input.Object marshaled to a generic map) and returns its Violations.
func (e *Engine) Evaluate(ctx context.Context, input map[string]any) ([]Violation, error) {
	rs, err := e.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("evaluating rego rules: %w", err)
	}

	var violations []Violation
	for _, result := range rs {
		for _, expr := range result.Expressions {
			items, ok := expr.Value.([]any)
			if !ok {
				continue
			}
			for _, item := range items {
				v, err := toViolation(item)
				if err != nil {
					return nil, err
				}
				violations = append(violations, v)
			}
		}
	}
	if err := checkDuplicateRuleIDs(violations); err != nil {
		return nil, err
	}
	return violations, nil
}

// checkDuplicateRuleIDs fails loudly when two deny entries share a rule_id
// but resolve to different severities. A single rule firing once per
// matched statement (e.g. each built-in rule's msg embeds the statement's
// Sid) is normal and must not trip this — Violation carries no provenance
// back to which rule/module produced it, so msg differing alone can't
// distinguish "one rule, multiple statements" from "two rules colliding
// on one ID." A severity mismatch under the same rule_id is the one
// signal checkable at this layer without that provenance, and it's the
// one that actually matters: suppress.Set matches on rule_id alone (see
// internal/suppress), so a suppression entry meant to silence one
// severity's worth of findings would silently also silence the other's.
// This can still miss two genuinely different rules that collide on
// both rule_id and severity — closing that gap needs static analysis of
// the loaded Rego source, not a runtime check on its output.
func checkDuplicateRuleIDs(violations []Violation) error {
	seen := make(map[string]Violation, len(violations))
	for _, v := range violations {
		if prev, ok := seen[v.RuleID]; ok {
			if NormalizeSeverity(prev.Severity) != NormalizeSeverity(v.Severity) {
				return fmt.Errorf("rule_id %q is used by more than one rule with different severities: %q (%s) vs %q (%s)",
					v.RuleID, prev.Msg, prev.Severity, v.Msg, v.Severity)
			}
			continue
		}
		seen[v.RuleID] = v
	}
	return nil
}

func toViolation(item any) (Violation, error) {
	m, ok := item.(map[string]any)
	if !ok {
		return Violation{}, fmt.Errorf("rule produced a non-object deny entry: %#v", item)
	}
	v := Violation{Severity: "medium"}
	if s, ok := m["msg"].(string); ok {
		v.Msg = s
	} else {
		return Violation{}, fmt.Errorf("rule deny entry missing required \"msg\" field: %#v", item)
	}
	if s, ok := m["rule_id"].(string); ok {
		v.RuleID = s
	} else {
		return Violation{}, fmt.Errorf("rule deny entry missing required \"rule_id\" field: %#v", item)
	}
	if s, ok := m["severity"].(string); ok {
		if NormalizeSeverity(s) == "" {
			return Violation{}, fmt.Errorf("rule %q has deny entry with unrecognized severity %q (want one of critical, error, high, medium, low, info, informational, suggestion)", v.RuleID, s)
		}
		v.Severity = s
	}
	return v, nil
}

// loadRegoDir reads every *.rego file under dir (recursively), each becoming
// one Source named by its path relative to dir.
func loadRegoDir(dir string) ([]Source, error) {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".rego") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	sources := make([]Source, 0, len(files))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(dir, f)
		if err != nil {
			rel = f
		}
		sources = append(sources, Source{Name: rel, Body: string(b)})
	}
	return sources, nil
}

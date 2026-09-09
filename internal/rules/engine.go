// Package rules evaluates scanned policy objects against Rego rule bundles:
// an embedded built-in bundle (see builtin/README.md) and an optional
// user-supplied directory, merged into one evaluation.
//
// Contract: every rule bundle is a Rego package under iamsentry.rules that
// sets a `deny` array. Each element must be an object with at least "msg"
// and "rule_id"; "severity" defaults to "medium" when absent. This package
// makes no assumption about how many rules exist — zero is valid and simply
// yields zero findings.
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
	return violations, nil
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
	if s, ok := m["severity"].(string); ok && s != "" {
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

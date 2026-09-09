// Command iamsentry scans IAM policy documents (raw JSON, or ACK
// iam.services.k8s.aws Role/Policy CRDs) against AWS IAM Access Analyzer
// and a local Rego rule engine, and renders the combined findings.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"

	"github.com/likesavabutworse/iamsentry/internal/awsval"
	"github.com/likesavabutworse/iamsentry/internal/denylist"
	"github.com/likesavabutworse/iamsentry/internal/input"
	"github.com/likesavabutworse/iamsentry/internal/policy"
	"github.com/likesavabutworse/iamsentry/internal/render"
	"github.com/likesavabutworse/iamsentry/internal/rules"
	"github.com/likesavabutworse/iamsentry/internal/suppress"
)

// suppressAnnotation is the ACK CRD annotation key honored for per-object
// suppressions — see internal/suppress package doc.
const suppressAnnotation = "iamsentry.io/suppress"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 || args[0] != "scan" {
		printUsage()
		return 2
	}

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	noAWS := fs.Bool("no-aws", false, "disable the AWS Access Analyzer layer (local Rego checks only)")
	rulesDir := fs.String("rules-dir", "", "directory of additional user-supplied .rego rules")
	threshold := fs.String("fail-on", render.SeverityLow, "minimum severity that causes a non-zero exit (ERROR|HIGH|MEDIUM|LOW|INFO)")
	noColor := fs.Bool("no-color", false, "disable ANSI color in output")
	suppressionsPath := fs.String("suppressions", "", "path to a suppressions YAML file (default: "+suppress.DefaultFileName+" in the current directory, if present)")
	ignore := fs.String("ignore", "", "comma-separated rule_ids to ignore for this run (not scoped, not reasoned — for transient local overrides, not for committing)")
	denyListFile := fs.String("deny-list", "", "path to a CheckAccessNotGranted deny-list YAML file — see denylist/examples/example.yaml. No default; off unless given")
	denyListDir := fs.String("deny-list-dir", "", "directory of deny-list YAML files, merged (mutually exclusive with --deny-list)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: iamsentry scan [flags] <file-or-directory>")
		return 2
	}
	path := fs.Arg(0)

	ctx := context.Background()

	objects, skipped, err := input.Scan(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	for _, s := range skipped {
		fmt.Fprintf(os.Stderr, "skipped %s: %s\n", s.SourceFile, s.Reason)
	}
	if len(objects) == 0 {
		fmt.Fprintln(os.Stderr, "no IAM policy documents or ACK Role/Policy CRDs found")
		return 2
	}

	engine, err := rules.NewEngine(ctx, mustBuiltins(), *rulesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	denyEntries, err := loadDenyList(*denyListFile, *denyListDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	var awsClient *awsval.Client
	if !*noAWS {
		cfg, err := awsconfig.LoadDefaultConfig(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: loading AWS config (pass --no-aws to skip the Access Analyzer layer): %v\n", err)
			return 2
		}
		awsClient = awsval.NewClient(accessanalyzer.NewFromConfig(cfg))
	} else if len(denyEntries) > 0 {
		fmt.Fprintln(os.Stderr, "warning: --deny-list/--deny-list-dir given with --no-aws — deny-list checks need the AWS layer and will be skipped")
	}

	var results []render.Result
	var annotationEntries []suppress.Entry
	for _, obj := range objects {
		regoIn, err := rules.ToInput(obj)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
		violations, err := engine.Evaluate(ctx, regoIn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error evaluating rules against %s: %v\n", obj.SourceFile, err)
			return 2
		}
		results = append(results, render.FromRego(obj.SourceFile, obj.Name, violations)...)

		if awsClient != nil {
			findings, err := runAccessAnalyzer(ctx, awsClient, obj)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error calling Access Analyzer for %s: %v\n", obj.SourceFile, err)
				return 2
			}
			results = append(results, render.FromAccessAnalyzer(obj.SourceFile, obj.Name, findings)...)

			denyFindings, err := runDenyListChecks(ctx, awsClient, obj, denyEntries)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error running deny-list checks for %s: %v\n", obj.SourceFile, err)
				return 2
			}
			results = append(results, render.FromAccessAnalyzer(obj.SourceFile, obj.Name, denyFindings)...)
		}

		if ids := obj.Annotations[suppressAnnotation]; ids != "" {
			annotationEntries = append(annotationEntries, suppress.FromAnnotation(splitCommaList(ids), obj.SourceFile, obj.Name)...)
		}
	}

	suppressionSet, err := loadSuppressions(*suppressionsPath, annotationEntries, splitCommaList(*ignore))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	kept, suppressed := suppress.Apply(results, suppressionSet)
	if len(suppressed) > 0 {
		fmt.Fprintf(os.Stderr, "suppressed %d finding(s) (see --suppressions / %s)\n", len(suppressed), suppress.DefaultFileName)
	}

	render.Write(os.Stdout, kept, !*noColor)
	return render.ExitCode(kept, *threshold)
}

// loadSuppressions merges, in order: an explicit --suppressions file (error
// if given but unreadable), or the default file name in the current
// directory if present (silently absent otherwise); per-object
// iamsentry.io/suppress annotation entries; and the --ignore flag.
func loadSuppressions(explicitPath string, annotationEntries []suppress.Entry, ignoreIDs []string) (suppress.Set, error) {
	var fileEntries []suppress.Entry

	path := explicitPath
	if path == "" {
		if _, err := os.Stat(suppress.DefaultFileName); err == nil {
			path = suppress.DefaultFileName
		}
	}
	if path != "" {
		entries, err := suppress.Load(path)
		if err != nil {
			return suppress.Set{}, err
		}
		fileEntries = entries
	}

	return suppress.NewSet(fileEntries, annotationEntries, suppress.FromIgnoreFlag(ignoreIDs)), nil
}

// loadDenyList loads deny-list entries from exactly one of file or dir; both
// empty means no deny-list checks run at all (the default — see package
// denylist's doc comment for why there's no built-in).
func loadDenyList(file, dir string) ([]denylist.Entry, error) {
	switch {
	case file != "" && dir != "":
		return nil, fmt.Errorf("--deny-list and --deny-list-dir are mutually exclusive")
	case file != "":
		return denylist.Load(file)
	case dir != "":
		return denylist.LoadDir(dir)
	default:
		return nil, nil
	}
}

func splitCommaList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// runAccessAnalyzer runs ValidatePolicy against every policy document found
// on obj: the trust policy and each inline policy for a Role, or the single
// document for a Policy/RawPolicy. The other three Access Analyzer
// operations aren't called here — see README's "Future extensions".
func runAccessAnalyzer(ctx context.Context, c *awsval.Client, obj input.Object) ([]awsval.Finding, error) {
	var all []awsval.Finding

	check := func(doc *policy.Document, policyType types.PolicyType, resourceType types.ValidatePolicyResourceType) error {
		if doc == nil {
			return nil
		}
		raw, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		findings, err := c.ValidatePolicy(ctx, string(raw), policyType, resourceType)
		if err != nil {
			return err
		}
		all = append(all, findings...)
		return nil
	}

	switch obj.Kind {
	case input.KindRawPolicy, input.KindPolicy:
		if err := check(obj.Document, types.PolicyTypeIdentityPolicy, ""); err != nil {
			return nil, err
		}
	case input.KindRole:
		// A trust policy has no Resource element by design — telling
		// ValidatePolicy it's specifically a role trust policy (rather than
		// a generic resource policy) is what suppresses the otherwise
		// spurious MISSING_RESOURCE finding. Confirmed against a live
		// account: omitting this fired MISSING_RESOURCE on a standard,
		// valid EKS Pod Identity trust policy.
		if err := check(obj.AssumeRolePolicy, types.PolicyTypeResourcePolicy, types.ValidatePolicyResourceTypeRoleTrust); err != nil {
			return nil, err
		}
		for _, inline := range obj.InlinePolicies {
			d := inline
			if err := check(&d, types.PolicyTypeIdentityPolicy, ""); err != nil {
				return nil, err
			}
		}
	}
	return all, nil
}

// runDenyListChecks runs CheckAccessNotGranted once per deny-list entry
// against every inline policy for a Role, or the single document for a
// Policy/RawPolicy — never against a Role's trust policy, since deny-list
// entries are about permissions grants, not "who can assume this role"
// (mirrors the same scoping choice the built-in Rego rules make). Always
// IDENTITY_POLICY: neither an inline policy nor a bare Policy/RawPolicy
// document is a resource-based policy in this tool's input model.
//
// Each entry is its own API call, deliberately: CheckAccessNotGranted
// returns one aggregate PASS/FAIL per call, not one result per Access
// object in a list, so batching entries into a single call would lose the
// ability to say *which* entry a FAIL belongs to. A FAIL's Finding is
// tagged with entry.ID via IssueCode (reusing the field ValidatePolicy
// puts its issue codes in) so it gets a stable, suppressible rule_id.
func runDenyListChecks(ctx context.Context, c *awsval.Client, obj input.Object, entries []denylist.Entry) ([]awsval.Finding, error) {
	if len(entries) == 0 {
		return nil, nil
	}

	var docs []*policy.Document
	switch obj.Kind {
	case input.KindRawPolicy, input.KindPolicy:
		docs = []*policy.Document{obj.Document}
	case input.KindRole:
		for _, inline := range obj.InlinePolicies {
			d := inline
			docs = append(docs, &d)
		}
	}

	var all []awsval.Finding
	for _, doc := range docs {
		if doc == nil {
			continue
		}
		raw, err := json.Marshal(doc)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			access := []types.Access{{Actions: entry.Actions, Resources: entry.Resources}}
			findings, err := c.CheckAccessNotGranted(ctx, string(raw), access, types.AccessCheckPolicyTypeIdentityPolicy)
			if err != nil {
				return nil, fmt.Errorf("deny-list entry %q: %w", entry.ID, err)
			}
			for i := range findings {
				findings[i].IssueCode = entry.ID
			}
			all = append(all, findings...)
		}
	}
	return all, nil
}

func mustBuiltins() []rules.Source {
	sources, err := rules.BuiltinSources()
	if err != nil {
		// The embedded bundle failing to load is a build defect, not a
		// runtime condition callers can act on.
		panic(fmt.Sprintf("iamsentry: embedded builtin rule bundle is broken: %v", err))
	}
	return sources
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `iamsentry — scan IAM policies against AWS Access Analyzer and local Rego rules

Usage:
  iamsentry scan [flags] <file-or-directory>

Flags:
  -no-aws            disable the AWS Access Analyzer layer (local Rego checks only)
  -rules-dir dir     directory of additional user-supplied .rego rules
  -fail-on level     minimum severity that causes a non-zero exit (default LOW)
  -no-color          disable ANSI color in output
  -suppressions path path to a suppressions YAML file (default: .iamsentry-suppressions.yaml if present)
  -ignore ids        comma-separated rule_ids to ignore for this run (unscoped, unreasoned, not for committing)
  -deny-list path    path to a CheckAccessNotGranted deny-list YAML file (no default; off unless given)
  -deny-list-dir dir directory of deny-list YAML files, merged (mutually exclusive with -deny-list)`)
}

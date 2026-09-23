// Package awsval wraps the four AWS IAM Access Analyzer policy-check APIs
// (ValidatePolicy, CheckAccessNotGranted, CheckNoNewAccess,
// CheckNoPublicAccess). All four are live AWS API calls requiring an
// authenticated session — none require a pre-provisioned Access Analyzer
// resource, but all need the matching access-analyzer:<Operation> IAM
// permission. This package's own tests (client_test.go) are mock-based
// only; see the README for what's been verified against a real account.
package awsval

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
)

// API is the subset of the accessanalyzer client this package depends on.
// Satisfied by *accessanalyzer.Client; a fake implementation backs the tests.
type API interface {
	ValidatePolicy(ctx context.Context, params *accessanalyzer.ValidatePolicyInput, optFns ...func(*accessanalyzer.Options)) (*accessanalyzer.ValidatePolicyOutput, error)
	CheckAccessNotGranted(ctx context.Context, params *accessanalyzer.CheckAccessNotGrantedInput, optFns ...func(*accessanalyzer.Options)) (*accessanalyzer.CheckAccessNotGrantedOutput, error)
	CheckNoNewAccess(ctx context.Context, params *accessanalyzer.CheckNoNewAccessInput, optFns ...func(*accessanalyzer.Options)) (*accessanalyzer.CheckNoNewAccessOutput, error)
	CheckNoPublicAccess(ctx context.Context, params *accessanalyzer.CheckNoPublicAccessInput, optFns ...func(*accessanalyzer.Options)) (*accessanalyzer.CheckNoPublicAccessOutput, error)
}

type Client struct {
	api API
}

func NewClient(api API) *Client {
	return &Client{api: api}
}

// Finding is a unified result shape for all four operations, so the renderer
// doesn't need to special-case each one. IssueCode is populated only by
// ValidatePolicy; the three custom checks leave it empty.
type Finding struct {
	Check     string // "ValidatePolicy" | "CheckAccessNotGranted" | "CheckNoNewAccess" | "CheckNoPublicAccess"
	Severity  string // "ERROR" | "SECURITY_WARNING" | "WARNING" | "SUGGESTION" (ValidatePolicy) or "FAIL"/"PASS" (custom checks)
	Message   string
	IssueCode string
	LearnMore string
	// StatementIndex is the 0-based index into the policy's Statement array
	// the finding points at; nil when AWS gave no statement location.
	StatementIndex *int
}

// ValidatePolicy has no severity field in the SDK response — only
// FindingType — so Finding.Severity is set from that.
func (c *Client) ValidatePolicy(ctx context.Context, policyDocument string, policyType types.PolicyType, resourceType types.ValidatePolicyResourceType) ([]Finding, error) {
	in := &accessanalyzer.ValidatePolicyInput{
		PolicyDocument: &policyDocument,
		PolicyType:     policyType,
	}
	if resourceType != "" {
		in.ValidatePolicyResourceType = resourceType
	}

	var findings []Finding
	paginator := accessanalyzer.NewValidatePolicyPaginator(c.api, in)
	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("access-analyzer:ValidatePolicy: %w", err)
		}
		for _, f := range out.Findings {
			findings = append(findings, Finding{
				Check:          "ValidatePolicy",
				Severity:       string(f.FindingType),
				Message:        deref(f.FindingDetails),
				IssueCode:      deref(f.IssueCode),
				LearnMore:      deref(f.LearnMoreLink),
				StatementIndex: statementIndex(f.Locations),
			})
		}
	}
	return findings, nil
}

// CheckAccessNotGranted returns nil findings on PASS.
func (c *Client) CheckAccessNotGranted(ctx context.Context, policyDocument string, access []types.Access, policyType types.AccessCheckPolicyType) ([]Finding, error) {
	out, err := c.api.CheckAccessNotGranted(ctx, &accessanalyzer.CheckAccessNotGrantedInput{
		PolicyDocument: &policyDocument,
		Access:         access,
		PolicyType:     policyType,
	})
	if err != nil {
		return nil, fmt.Errorf("access-analyzer:CheckAccessNotGranted: %w", err)
	}
	if out.Result == types.CheckAccessNotGrantedResultPass {
		return nil, nil
	}
	return reasonsToFindings("CheckAccessNotGranted", deref(out.Message), out.Reasons), nil
}

// CheckNoNewAccess returns nil findings on PASS.
func (c *Client) CheckNoNewAccess(ctx context.Context, newPolicyDocument, existingPolicyDocument string, policyType types.AccessCheckPolicyType) ([]Finding, error) {
	out, err := c.api.CheckNoNewAccess(ctx, &accessanalyzer.CheckNoNewAccessInput{
		NewPolicyDocument:      &newPolicyDocument,
		ExistingPolicyDocument: &existingPolicyDocument,
		PolicyType:             policyType,
	})
	if err != nil {
		return nil, fmt.Errorf("access-analyzer:CheckNoNewAccess: %w", err)
	}
	if out.Result == types.CheckNoNewAccessResultPass {
		return nil, nil
	}
	return reasonsToFindings("CheckNoNewAccess", deref(out.Message), out.Reasons), nil
}

// CheckNoPublicAccess returns nil findings on PASS.
func (c *Client) CheckNoPublicAccess(ctx context.Context, policyDocument string, resourceType types.AccessCheckResourceType) ([]Finding, error) {
	out, err := c.api.CheckNoPublicAccess(ctx, &accessanalyzer.CheckNoPublicAccessInput{
		PolicyDocument: &policyDocument,
		ResourceType:   resourceType,
	})
	if err != nil {
		return nil, fmt.Errorf("access-analyzer:CheckNoPublicAccess: %w", err)
	}
	if out.Result == types.CheckNoPublicAccessResultPass {
		return nil, nil
	}
	return reasonsToFindings("CheckNoPublicAccess", deref(out.Message), out.Reasons), nil
}

func reasonsToFindings(check, message string, reasons []types.ReasonSummary) []Finding {
	if len(reasons) == 0 {
		return []Finding{{Check: check, Severity: "FAIL", Message: message}}
	}
	findings := make([]Finding, 0, len(reasons))
	for _, r := range reasons {
		msg := deref(r.Description)
		if sid := deref(r.StatementId); sid != "" {
			msg = fmt.Sprintf("[Sid: %s] %s", sid, msg)
		} else if r.StatementIndex != nil {
			msg = fmt.Sprintf("[statement %d] %s", *r.StatementIndex, msg)
		}
		f := Finding{Check: check, Severity: "FAIL", Message: msg}
		if r.StatementIndex != nil {
			i := int(*r.StatementIndex)
			f.StatementIndex = &i
		}
		findings = append(findings, f)
	}
	return findings
}

// statementIndex extracts the Statement index from the first location's
// path (e.g. Statement[2].Resource[0] -> 2). Only the first location is
// used because a finding is reported at one line.
func statementIndex(locs []types.Location) *int {
	if len(locs) == 0 || len(locs[0].Path) < 2 {
		return nil
	}
	path := locs[0].Path
	if k, ok := path[0].(*types.PathElementMemberKey); !ok || k.Value != "Statement" {
		return nil
	}
	idx, ok := path[1].(*types.PathElementMemberIndex)
	if !ok {
		return nil
	}
	i := int(idx.Value)
	return &i
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

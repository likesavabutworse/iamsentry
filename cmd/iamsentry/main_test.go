package main

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"

	"github.com/likesavabutworse/iamsentry/internal/awsval"
	"github.com/likesavabutworse/iamsentry/internal/denylist"
	"github.com/likesavabutworse/iamsentry/internal/input"
	"github.com/likesavabutworse/iamsentry/internal/policy"
)

// capturingAPI records every ValidatePolicyInput/CheckAccessNotGrantedInput
// it's called with, so tests can assert exactly what this command sends —
// the thing a live-only test can't check without an account, and the thing
// that was actually wrong once already (see the comment in runAccessAnalyzer).
type capturingAPI struct {
	calls []*accessanalyzer.ValidatePolicyInput

	canCalls    []*accessanalyzer.CheckAccessNotGrantedInput
	canResponse func(*accessanalyzer.CheckAccessNotGrantedInput) *accessanalyzer.CheckAccessNotGrantedOutput
}

func (f *capturingAPI) ValidatePolicy(_ context.Context, in *accessanalyzer.ValidatePolicyInput, _ ...func(*accessanalyzer.Options)) (*accessanalyzer.ValidatePolicyOutput, error) {
	f.calls = append(f.calls, in)
	return &accessanalyzer.ValidatePolicyOutput{}, nil
}
func (f *capturingAPI) CheckAccessNotGranted(_ context.Context, in *accessanalyzer.CheckAccessNotGrantedInput, _ ...func(*accessanalyzer.Options)) (*accessanalyzer.CheckAccessNotGrantedOutput, error) {
	f.canCalls = append(f.canCalls, in)
	if f.canResponse != nil {
		return f.canResponse(in), nil
	}
	return &accessanalyzer.CheckAccessNotGrantedOutput{Result: types.CheckAccessNotGrantedResultPass}, nil
}
func (f *capturingAPI) CheckNoNewAccess(context.Context, *accessanalyzer.CheckNoNewAccessInput, ...func(*accessanalyzer.Options)) (*accessanalyzer.CheckNoNewAccessOutput, error) {
	return &accessanalyzer.CheckNoNewAccessOutput{}, nil
}
func (f *capturingAPI) CheckNoPublicAccess(context.Context, *accessanalyzer.CheckNoPublicAccessInput, ...func(*accessanalyzer.Options)) (*accessanalyzer.CheckNoPublicAccessOutput, error) {
	return &accessanalyzer.CheckNoPublicAccessOutput{}, nil
}

// TestRunAccessAnalyzer_RoleTrustPolicyUsesRoleTrustResourceType is a
// regression test for a bug caught only by testing against a live account:
// omitting ValidatePolicyResourceType on a Role's trust policy made AWS
// treat it as a generic resource policy and fire a spurious
// MISSING_RESOURCE finding on a standard, valid trust policy (trust
// policies have no Resource element by design).
func TestRunAccessAnalyzer_RoleTrustPolicyUsesRoleTrustResourceType(t *testing.T) {
	fake := &capturingAPI{}
	c := awsval.NewClient(fake)

	obj := input.Object{
		Kind: input.KindRole,
		Name: "svc-example-prod",
		AssumeRolePolicy: &policy.Document{
			Statement: []policy.Statement{{Effect: "Allow", Action: policy.StringOrSlice{"sts:AssumeRole"}}},
		},
		InlinePolicies: map[string]policy.Document{
			"perms": {
				Statement: []policy.Statement{{Effect: "Allow", Action: policy.StringOrSlice{"s3:GetObject"}, Resource: policy.StringOrSlice{"arn:aws:s3:::b/*"}}},
			},
		},
	}

	if _, err := runAccessAnalyzer(context.Background(), c, obj); err != nil {
		t.Fatalf("runAccessAnalyzer: %v", err)
	}
	if len(fake.calls) != 2 {
		t.Fatalf("expected 2 ValidatePolicy calls (trust + inline), got %d", len(fake.calls))
	}

	var trustCall, inlineCall *accessanalyzer.ValidatePolicyInput
	for _, call := range fake.calls {
		if call.PolicyType == types.PolicyTypeResourcePolicy {
			trustCall = call
		} else {
			inlineCall = call
		}
	}

	if trustCall == nil {
		t.Fatal("no call used PolicyType RESOURCE_POLICY for the trust policy")
	}
	if trustCall.ValidatePolicyResourceType != types.ValidatePolicyResourceTypeRoleTrust {
		t.Errorf("trust policy call: ValidatePolicyResourceType = %q, want %q",
			trustCall.ValidatePolicyResourceType, types.ValidatePolicyResourceTypeRoleTrust)
	}

	if inlineCall == nil {
		t.Fatal("no call used PolicyType IDENTITY_POLICY for the inline policy")
	}
	if inlineCall.ValidatePolicyResourceType != "" {
		t.Errorf("inline policy call: ValidatePolicyResourceType = %q, want empty", inlineCall.ValidatePolicyResourceType)
	}
}

func TestRunDenyListChecks(t *testing.T) {
	entries := []denylist.Entry{
		{ID: "no-bucket-delete", Actions: []string{"s3:DeleteBucket"}},
		{ID: "protect-state", Resources: []string{"arn:aws:s3:::state/*"}},
	}

	fake := &capturingAPI{
		// Fail only the "protect-state" entry (identified by its Resources),
		// so the test can assert the resulting Finding is tagged with the
		// right entry.ID and not the other one.
		canResponse: func(in *accessanalyzer.CheckAccessNotGrantedInput) *accessanalyzer.CheckAccessNotGrantedOutput {
			if len(in.Access) == 1 && len(in.Access[0].Resources) == 1 && in.Access[0].Resources[0] == "arn:aws:s3:::state/*" {
				msg := "fail"
				return &accessanalyzer.CheckAccessNotGrantedOutput{Result: types.CheckAccessNotGrantedResultFail, Message: &msg}
			}
			return &accessanalyzer.CheckAccessNotGrantedOutput{Result: types.CheckAccessNotGrantedResultPass}
		},
	}
	c := awsval.NewClient(fake)

	obj := input.Object{
		Kind: input.KindRole,
		Name: "svc-example-prod",
		// A trust policy is present, but runDenyListChecks must never touch
		// it — deny-list entries are about permissions grants, not "who can
		// assume this role."
		AssumeRolePolicy: &policy.Document{
			Statement: []policy.Statement{{Effect: "Allow", Action: policy.StringOrSlice{"sts:AssumeRole"}}},
		},
		InlinePolicies: map[string]policy.Document{
			"perms-a": {Statement: []policy.Statement{{Effect: "Allow", Action: policy.StringOrSlice{"s3:GetObject"}, Resource: policy.StringOrSlice{"arn:aws:s3:::b/*"}}}},
			"perms-b": {Statement: []policy.Statement{{Effect: "Allow", Action: policy.StringOrSlice{"s3:PutObject"}, Resource: policy.StringOrSlice{"arn:aws:s3:::b/*"}}}},
		},
	}

	findings, err := runDenyListChecks(context.Background(), c, obj, entries)
	if err != nil {
		t.Fatalf("runDenyListChecks: %v", err)
	}

	// 2 entries x 2 inline policies = 4 calls; never against the trust policy.
	if len(fake.canCalls) != 4 {
		t.Fatalf("expected 4 CheckAccessNotGranted calls, got %d", len(fake.canCalls))
	}
	for _, call := range fake.canCalls {
		if call.PolicyType != types.AccessCheckPolicyTypeIdentityPolicy {
			t.Errorf("PolicyType = %v, want IDENTITY_POLICY", call.PolicyType)
		}
	}

	// One FAIL per inline policy (2 inline policies x 1 failing entry).
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.IssueCode != "protect-state" {
			t.Errorf("Finding.IssueCode = %q, want the failing entry's id %q", f.IssueCode, "protect-state")
		}
	}
}

func TestRunDenyListChecks_NoEntriesMakesNoCalls(t *testing.T) {
	fake := &capturingAPI{}
	c := awsval.NewClient(fake)
	obj := input.Object{Kind: input.KindRawPolicy, Document: &policy.Document{}}

	findings, err := runDenyListChecks(context.Background(), c, obj, nil)
	if err != nil {
		t.Fatalf("runDenyListChecks: %v", err)
	}
	if findings != nil || len(fake.canCalls) != 0 {
		t.Errorf("expected no calls and no findings with an empty deny list, got %d calls, %v findings", len(fake.canCalls), findings)
	}
}

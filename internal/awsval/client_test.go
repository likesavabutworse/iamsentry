package awsval

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
)

// fakeAPI is a hand-written stub, not a live AWS call — see package doc.
type fakeAPI struct {
	validatePolicy        func(*accessanalyzer.ValidatePolicyInput) (*accessanalyzer.ValidatePolicyOutput, error)
	checkAccessNotGranted func(*accessanalyzer.CheckAccessNotGrantedInput) (*accessanalyzer.CheckAccessNotGrantedOutput, error)
	checkNoNewAccess      func(*accessanalyzer.CheckNoNewAccessInput) (*accessanalyzer.CheckNoNewAccessOutput, error)
	checkNoPublicAccess   func(*accessanalyzer.CheckNoPublicAccessInput) (*accessanalyzer.CheckNoPublicAccessOutput, error)
}

func (f *fakeAPI) ValidatePolicy(_ context.Context, in *accessanalyzer.ValidatePolicyInput, _ ...func(*accessanalyzer.Options)) (*accessanalyzer.ValidatePolicyOutput, error) {
	return f.validatePolicy(in)
}

func (f *fakeAPI) CheckAccessNotGranted(_ context.Context, in *accessanalyzer.CheckAccessNotGrantedInput, _ ...func(*accessanalyzer.Options)) (*accessanalyzer.CheckAccessNotGrantedOutput, error) {
	return f.checkAccessNotGranted(in)
}

func (f *fakeAPI) CheckNoNewAccess(_ context.Context, in *accessanalyzer.CheckNoNewAccessInput, _ ...func(*accessanalyzer.Options)) (*accessanalyzer.CheckNoNewAccessOutput, error) {
	return f.checkNoNewAccess(in)
}

func (f *fakeAPI) CheckNoPublicAccess(_ context.Context, in *accessanalyzer.CheckNoPublicAccessInput, _ ...func(*accessanalyzer.Options)) (*accessanalyzer.CheckNoPublicAccessOutput, error) {
	return f.checkNoPublicAccess(in)
}

func strp(s string) *string { return &s }

func TestValidatePolicy_MapsFindings(t *testing.T) {
	fake := &fakeAPI{
		validatePolicy: func(in *accessanalyzer.ValidatePolicyInput) (*accessanalyzer.ValidatePolicyOutput, error) {
			if in.PolicyType != types.PolicyTypeIdentityPolicy {
				t.Errorf("PolicyType = %v, want IDENTITY_POLICY", in.PolicyType)
			}
			return &accessanalyzer.ValidatePolicyOutput{
				Findings: []types.ValidatePolicyFinding{
					{
						FindingType:    types.ValidatePolicyFindingTypeSecurityWarning,
						FindingDetails: strp("resource-star finding"),
						IssueCode:      strp("SecurityWarningActionSetResourceGetsFullAccessOnDatabaseServices"),
						LearnMoreLink:  strp("https://example.com"),
					},
				},
			}, nil
		},
	}

	c := NewClient(fake)
	findings, err := c.ValidatePolicy(context.Background(), `{"Version":"2012-10-17","Statement":[]}`, types.PolicyTypeIdentityPolicy, "")
	if err != nil {
		t.Fatalf("ValidatePolicy: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Check != "ValidatePolicy" || f.Severity != "SECURITY_WARNING" || f.IssueCode == "" {
		t.Errorf("unexpected finding: %+v", f)
	}
}

func TestCheckAccessNotGranted_PassYieldsNoFindings(t *testing.T) {
	fake := &fakeAPI{
		checkAccessNotGranted: func(in *accessanalyzer.CheckAccessNotGrantedInput) (*accessanalyzer.CheckAccessNotGrantedOutput, error) {
			return &accessanalyzer.CheckAccessNotGrantedOutput{Result: types.CheckAccessNotGrantedResultPass}, nil
		},
	}
	c := NewClient(fake)
	findings, err := c.CheckAccessNotGranted(context.Background(), `{}`, []types.Access{{Actions: []string{"s3:DeleteBucket"}}}, types.AccessCheckPolicyTypeIdentityPolicy)
	if err != nil {
		t.Fatalf("CheckAccessNotGranted: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings on PASS, got %v", findings)
	}
}

func TestCheckAccessNotGranted_FailYieldsReasons(t *testing.T) {
	idx := int32(2)
	fake := &fakeAPI{
		checkAccessNotGranted: func(in *accessanalyzer.CheckAccessNotGrantedInput) (*accessanalyzer.CheckAccessNotGrantedOutput, error) {
			return &accessanalyzer.CheckAccessNotGrantedOutput{
				Result:  types.CheckAccessNotGrantedResultFail,
				Message: strp("policy might allow forbidden access"),
				Reasons: []types.ReasonSummary{
					{Description: strp("statement grants s3:DeleteBucket"), StatementIndex: &idx},
				},
			}, nil
		},
	}
	c := NewClient(fake)
	findings, err := c.CheckAccessNotGranted(context.Background(), `{}`, []types.Access{{Actions: []string{"s3:DeleteBucket"}}}, types.AccessCheckPolicyTypeIdentityPolicy)
	if err != nil {
		t.Fatalf("CheckAccessNotGranted: %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != "FAIL" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}

func TestCheckNoNewAccess_Pass(t *testing.T) {
	fake := &fakeAPI{
		checkNoNewAccess: func(in *accessanalyzer.CheckNoNewAccessInput) (*accessanalyzer.CheckNoNewAccessOutput, error) {
			return &accessanalyzer.CheckNoNewAccessOutput{Result: types.CheckNoNewAccessResultPass}, nil
		},
	}
	c := NewClient(fake)
	findings, err := c.CheckNoNewAccess(context.Background(), `{}`, `{}`, types.AccessCheckPolicyTypeIdentityPolicy)
	if err != nil {
		t.Fatalf("CheckNoNewAccess: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings on PASS, got %v", findings)
	}
}

func TestCheckNoPublicAccess_Fail(t *testing.T) {
	fake := &fakeAPI{
		checkNoPublicAccess: func(in *accessanalyzer.CheckNoPublicAccessInput) (*accessanalyzer.CheckNoPublicAccessOutput, error) {
			return &accessanalyzer.CheckNoPublicAccessOutput{
				Result:  types.CheckNoPublicAccessResultFail,
				Message: strp("bucket policy allows public access"),
			}, nil
		},
	}
	c := NewClient(fake)
	findings, err := c.CheckNoPublicAccess(context.Background(), `{}`, types.AccessCheckResourceTypeS3Bucket)
	if err != nil {
		t.Fatalf("CheckNoPublicAccess: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %v", findings)
	}
}

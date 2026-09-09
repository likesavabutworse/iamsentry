package input

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", p, err)
	}
	return p
}

func TestScan_RawJSONPolicy(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "policy.json", `{
		"Version": "2012-10-17",
		"Statement": [
			{"Sid": "AllowGet", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"}
		]
	}`)

	objs, skipped, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("expected no skipped files, got %v", skipped)
	}
	if len(objs) != 1 {
		t.Fatalf("expected 1 object, got %d", len(objs))
	}
	obj := objs[0]
	if obj.Kind != KindRawPolicy {
		t.Errorf("Kind = %v, want %v", obj.Kind, KindRawPolicy)
	}
	if obj.Document == nil || len(obj.Document.Statement) != 1 {
		t.Fatalf("Document not parsed correctly: %+v", obj.Document)
	}
	stmt := obj.Document.Statement[0]
	if len(stmt.Action) != 1 || stmt.Action[0] != "s3:GetObject" {
		t.Errorf("Action = %v, want [s3:GetObject] (single string should normalize to a slice)", stmt.Action)
	}
}

func TestScan_AckRole(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "role.yaml", `
apiVersion: iam.services.k8s.aws/v1alpha1
kind: Role
metadata:
  name: svc-example-prod
  annotations:
    iamsentry.io/suppress: "example.tags.owner_required, some.other.rule"
spec:
  name: svc-example-prod
  assumeRolePolicyDocument: |
    {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"pods.eks.amazonaws.com"},"Action":["sts:AssumeRole","sts:TagSession"]}]}
  inlinePolicies:
    service-permissions: |
      {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::bucket/*"]}]}
  policies:
    - arn:aws:iam::aws:policy/ReadOnlyAccess
  tags:
    - key: owner
      value: platform
`)

	objs, skipped, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("expected no skipped files, got %v", skipped)
	}
	if len(objs) != 1 {
		t.Fatalf("expected 1 object, got %d", len(objs))
	}
	obj := objs[0]
	if obj.Kind != KindRole {
		t.Fatalf("Kind = %v, want %v", obj.Kind, KindRole)
	}
	if obj.Name != "svc-example-prod" {
		t.Errorf("Name = %q", obj.Name)
	}
	if obj.AssumeRolePolicy == nil || len(obj.AssumeRolePolicy.Statement) != 1 {
		t.Fatalf("AssumeRolePolicy not parsed: %+v", obj.AssumeRolePolicy)
	}
	if len(obj.InlinePolicies) != 1 || len(obj.InlinePolicies["service-permissions"].Statement) != 1 {
		t.Fatalf("InlinePolicies not parsed: %+v", obj.InlinePolicies)
	}
	if len(obj.AttachedPolicyARNs) != 1 || obj.AttachedPolicyARNs[0] != "arn:aws:iam::aws:policy/ReadOnlyAccess" {
		t.Errorf("AttachedPolicyARNs = %v", obj.AttachedPolicyARNs)
	}
	if obj.Tags["owner"] != "platform" {
		t.Errorf("Tags[owner] = %q, want platform", obj.Tags["owner"])
	}
	if obj.Annotations["iamsentry.io/suppress"] != "example.tags.owner_required, some.other.rule" {
		t.Errorf("Annotations[iamsentry.io/suppress] = %q", obj.Annotations["iamsentry.io/suppress"])
	}
}

func TestScan_AckPolicy(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "policy.yaml", `
apiVersion: iam.services.k8s.aws/v1alpha1
kind: Policy
spec:
  name: MyBoundary
  policyDocument: |
    {"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"iam:*","Resource":"*"}]}
`)

	objs, _, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(objs) != 1 || objs[0].Kind != KindPolicy || objs[0].Name != "MyBoundary" {
		t.Fatalf("unexpected result: %+v", objs)
	}
}

func TestScan_UnsupportedKindIsSkippedNotFatal(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "user.yaml", `
apiVersion: iam.services.k8s.aws/v1alpha1
kind: User
spec:
  name: someone
`)

	objs, skipped, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(objs) != 0 {
		t.Fatalf("expected no objects, got %v", objs)
	}
	if len(skipped) != 1 {
		t.Fatalf("expected 1 skipped entry, got %v", skipped)
	}
}

func TestScan_MultiDocumentYAML(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "multi.yaml", `
apiVersion: iam.services.k8s.aws/v1alpha1
kind: Policy
spec:
  name: PolicyA
  policyDocument: '{"Version":"2012-10-17","Statement":[]}'
---
apiVersion: iam.services.k8s.aws/v1alpha1
kind: Policy
spec:
  name: PolicyB
  policyDocument: '{"Version":"2012-10-17","Statement":[]}'
`)

	objs, _, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(objs) != 2 {
		t.Fatalf("expected 2 objects from multi-doc YAML, got %d", len(objs))
	}
}

func TestScan_IgnoresUnrelatedManifests(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "deployment.yaml", `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
`)

	objs, skipped, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(objs) != 0 {
		t.Fatalf("expected no objects, got %v", objs)
	}
	if len(skipped) != 1 {
		t.Fatalf("expected 1 skipped entry, got %v", skipped)
	}
}

// TestScan_MalformedJSONIsHardError is the evidence behind the README's "A
// gap Helm/kubectl/ArgoCD structurally can't see" claim: the ACK CRD schema
// only declares inlinePolicies as a string field, so schema validation
// (Helm, kubectl, ArgoCD) never looks inside it. A malformed JSON blob is
// schema-valid and would sail straight through all three. Scan must reject
// it as a hard error, not a soft finding, with no AWS dependency.
func TestScan_MalformedJSONIsHardError(t *testing.T) {
	_, _, err := Scan("../../testdata/malformed/broken-inline-policy.yaml")
	if err == nil {
		t.Fatal("expected an error for malformed JSON in inlinePolicies, got nil")
	}
	if !strings.Contains(err.Error(), "parsing IAM policy document") {
		t.Errorf("error = %q, want it to name the failing field/parse step", err.Error())
	}
}

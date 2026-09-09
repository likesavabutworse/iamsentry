// Package input discovers and parses IAM policy sources: raw IAM policy JSON
// (the universal shape, produced by any pipeline) and ACK
// (aws-controllers-k8s) iam.services.k8s.aws Role/Policy CRDs. Both are
// consumed as already-rendered output — this package never runs Helm,
// Kustomize, or anything else; the caller renders first.
package input

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/likesavabutworse/iamsentry/internal/policy"
	"gopkg.in/yaml.v3"
)

// Kind identifies what kind of object a scanned document turned out to be.
type Kind string

const (
	KindRawPolicy Kind = "RawPolicy" // a bare {"Version":..., "Statement":[...]} document
	KindRole      Kind = "Role"      // iam.services.k8s.aws Role CRD
	KindPolicy    Kind = "Policy"    // iam.services.k8s.aws Policy CRD
)

// ackAPIGroupPrefix is the API group all supported ACK IAM CRDs live under.
// kind: InstanceProfile, Group, and User in this group are recognized but
// intentionally not scanned (out of scope) — see unsupportedAckKinds.
const ackAPIGroupPrefix = "iam.services.k8s.aws"

var unsupportedAckKinds = map[string]bool{
	"InstanceProfile": true,
	"Group":           true,
	"User":            true,
}

// Object is one normalized scanned unit, ready for both check layers.
type Object struct {
	SourceFile string
	Kind       Kind
	Name       string // ACK metadata.name / spec.name; empty for RawPolicy

	// Populated for KindRawPolicy and KindPolicy.
	Document *policy.Document

	// Populated for KindRole.
	AssumeRolePolicy   *policy.Document
	InlinePolicies     map[string]policy.Document
	AttachedPolicyARNs []string

	Tags map[string]string

	// Annotations holds metadata.annotations for KindRole/KindPolicy objects
	// (empty for RawPolicy, which has no metadata) — the CLI reads it for
	// the per-object "iamsentry.io/suppress" annotation.
	Annotations map[string]string
}

// Skipped records a document that was read but not recognized as a scannable
// object (unsupported kind, or neither an ACK CRD nor a raw policy document).
type Skipped struct {
	SourceFile string
	Reason     string
}

// Scan reads path (a single file or a directory, scanned recursively) and
// returns every recognized Object plus a record of anything skipped.
func Scan(path string) ([]Object, []Skipped, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var files []string
	if info.IsDir() {
		err := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if isScannableExt(p) {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, nil, fmt.Errorf("walking %s: %w", path, err)
		}
	} else {
		files = []string{path}
	}
	sort.Strings(files)

	var objects []Object
	var skipped []Skipped
	for _, f := range files {
		objs, skips, err := scanFile(f)
		if err != nil {
			return nil, nil, err
		}
		objects = append(objects, objs...)
		skipped = append(skipped, skips...)
	}
	return objects, skipped, nil
}

func isScannableExt(p string) bool {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".yaml", ".yml", ".json":
		return true
	default:
		return false
	}
}

// scanFile decodes every YAML document in f (a plain JSON file is one
// document; JSON is valid YAML so both go through the same decoder) and
// classifies each one.
func scanFile(f string) ([]Object, []Skipped, error) {
	file, err := os.Open(f)
	if err != nil {
		return nil, nil, fmt.Errorf("opening %s: %w", f, err)
	}
	defer file.Close()

	dec := yaml.NewDecoder(file)
	var objects []Object
	var skipped []Skipped
	for {
		var doc map[string]any
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("parsing %s: %w", f, err)
		}
		if len(doc) == 0 {
			continue
		}
		obj, skip, err := classify(f, doc)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", f, err)
		}
		if skip != "" {
			skipped = append(skipped, Skipped{SourceFile: f, Reason: skip})
			continue
		}
		objects = append(objects, *obj)
	}
	return objects, skipped, nil
}

func classify(sourceFile string, doc map[string]any) (*Object, string, error) {
	kindStr, _ := doc["kind"].(string)
	apiVersion, _ := doc["apiVersion"].(string)

	switch {
	case kindStr != "" && strings.HasPrefix(apiVersion, ackAPIGroupPrefix):
		if unsupportedAckKinds[kindStr] {
			return nil, fmt.Sprintf("kind: %s is out of scope (not scanned)", kindStr), nil
		}
		switch kindStr {
		case "Role":
			obj, err := parseAckRole(sourceFile, doc)
			return obj, "", err
		case "Policy":
			obj, err := parseAckPolicy(sourceFile, doc)
			return obj, "", err
		default:
			return nil, fmt.Sprintf("unrecognized %s kind: %s", ackAPIGroupPrefix, kindStr), nil
		}

	case looksLikePolicyDocument(doc):
		obj, err := parseRawPolicy(sourceFile, doc)
		return obj, "", err

	default:
		return nil, "not an IAM policy document or a supported ACK CRD", nil
	}
}

// looksLikePolicyDocument recognizes the bare {"Version":..., "Statement":[...]}
// shape used by raw IAM policy JSON/YAML, independent of which pipeline
// produced it.
func looksLikePolicyDocument(doc map[string]any) bool {
	_, hasStatement := doc["Statement"]
	return hasStatement
}

func parseRawPolicy(sourceFile string, doc map[string]any) (*Object, error) {
	d, err := decodeDocument(doc)
	if err != nil {
		return nil, fmt.Errorf("decoding raw policy document: %w", err)
	}
	return &Object{
		SourceFile: sourceFile,
		Kind:       KindRawPolicy,
		Document:   &d,
	}, nil
}

func parseAckPolicy(sourceFile string, doc map[string]any) (*Object, error) {
	spec, _ := doc["spec"].(map[string]any)
	name, _ := spec["name"].(string)
	docStr, _ := spec["policyDocument"].(string)
	if docStr == "" {
		return nil, fmt.Errorf("kind: Policy %q has no spec.policyDocument", name)
	}
	d, err := policy.ParseDocument(docStr)
	if err != nil {
		return nil, fmt.Errorf("kind: Policy %q spec.policyDocument: %w", name, err)
	}
	return &Object{
		SourceFile:  sourceFile,
		Kind:        KindPolicy,
		Name:        name,
		Document:    &d,
		Tags:        parseAckTags(spec["tags"]),
		Annotations: parseAckAnnotations(doc),
	}, nil
}

func parseAckRole(sourceFile string, doc map[string]any) (*Object, error) {
	spec, _ := doc["spec"].(map[string]any)
	name, _ := spec["name"].(string)

	obj := &Object{
		SourceFile:  sourceFile,
		Kind:        KindRole,
		Name:        name,
		Tags:        parseAckTags(spec["tags"]),
		Annotations: parseAckAnnotations(doc),
	}

	if trustStr, ok := spec["assumeRolePolicyDocument"].(string); ok && trustStr != "" {
		d, err := policy.ParseDocument(trustStr)
		if err != nil {
			return nil, fmt.Errorf("kind: Role %q spec.assumeRolePolicyDocument: %w", name, err)
		}
		obj.AssumeRolePolicy = &d
	}

	if inline, ok := spec["inlinePolicies"].(map[string]any); ok {
		obj.InlinePolicies = make(map[string]policy.Document, len(inline))
		for policyName, v := range inline {
			docStr, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("kind: Role %q spec.inlinePolicies[%q] is not a string", name, policyName)
			}
			d, err := policy.ParseDocument(docStr)
			if err != nil {
				return nil, fmt.Errorf("kind: Role %q spec.inlinePolicies[%q]: %w", name, policyName, err)
			}
			obj.InlinePolicies[policyName] = d
		}
	}

	if arns, ok := spec["policies"].([]any); ok {
		for _, a := range arns {
			if s, ok := a.(string); ok {
				obj.AttachedPolicyARNs = append(obj.AttachedPolicyARNs, s)
			}
		}
	}

	return obj, nil
}

// parseAckAnnotations extracts metadata.annotations (a plain string map in
// every k8s object) from a decoded ACK CRD document.
func parseAckAnnotations(doc map[string]any) map[string]string {
	metadata, _ := doc["metadata"].(map[string]any)
	raw, _ := metadata["annotations"].(map[string]any)
	if len(raw) == 0 {
		return nil
	}
	annotations := make(map[string]string, len(raw))
	for k, v := range raw {
		if s, ok := v.(string); ok {
			annotations[k] = s
		}
	}
	return annotations
}

func parseAckTags(v any) map[string]string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	tags := make(map[string]string, len(list))
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		k, _ := m["key"].(string)
		val, _ := m["value"].(string)
		if k != "" {
			tags[k] = val
		}
	}
	return tags
}

// decodeDocument re-marshals a generically-decoded YAML/JSON map through
// encoding/json so it lands in policy.Document's typed, tagged fields
// (including StringOrSlice normalization for Action/Resource).
func decodeDocument(doc map[string]any) (policy.Document, error) {
	b, err := json.Marshal(doc)
	if err != nil {
		return policy.Document{}, err
	}
	var d policy.Document
	if err := json.Unmarshal(b, &d); err != nil {
		return policy.Document{}, err
	}
	return d, nil
}

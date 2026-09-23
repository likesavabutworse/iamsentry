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

	// Line is the 1-based line where the object starts in SourceFile; 0 if
	// unknown. The *Location fields below point at individual policy
	// documents and their statements within the object.
	Line                     int
	DocumentLocation         PolicyLocation
	AssumeRolePolicyLocation PolicyLocation
	InlinePolicyLocations    map[string]PolicyLocation

	// Annotations holds metadata.annotations for KindRole/KindPolicy objects
	// (empty for RawPolicy, which has no metadata) — the CLI reads it for
	// the per-object "iamsentry.io/suppress" annotation.
	Annotations map[string]string
}

// PolicyLocation records where one policy document sits in its source file.
// Zero values mean unknown.
type PolicyLocation struct {
	// Line is the document's first line for a raw policy, or the line of
	// the CRD field key (e.g. "policyDocument:") that embeds it.
	Line int
	// StatementLines holds one line per Statement index. Nil when the
	// embedding can't be mapped back to file lines — only a literal ("|")
	// block scalar preserves the embedded JSON's line breaks verbatim.
	StatementLines []int
}

// LineFor returns the line of statement stmt, falling back to the
// document's own line when stmt is nil or out of range.
func (l PolicyLocation) LineFor(stmt *int) int {
	if stmt != nil && *stmt >= 0 && *stmt < len(l.StatementLines) {
		return l.StatementLines[*stmt]
	}
	return l.Line
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
		// Decoding to a yaml.Node first, rather than straight into a map,
		// keeps the line numbers that findings are reported against.
		var node yaml.Node
		err := dec.Decode(&node)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("parsing %s: %w", f, err)
		}
		var doc map[string]any
		if err := node.Decode(&doc); err != nil {
			return nil, nil, fmt.Errorf("parsing %s: %w", f, err)
		}
		if len(doc) == 0 {
			continue
		}
		root := node.Content[0]
		obj, skip, err := classify(f, doc, root)
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

func classify(sourceFile string, doc map[string]any, root *yaml.Node) (*Object, string, error) {
	kindStr, _ := doc["kind"].(string)
	apiVersion, _ := doc["apiVersion"].(string)

	switch {
	case kindStr != "" && strings.HasPrefix(apiVersion, ackAPIGroupPrefix):
		if unsupportedAckKinds[kindStr] {
			return nil, fmt.Sprintf("kind: %s is out of scope (not scanned)", kindStr), nil
		}
		switch kindStr {
		case "Role":
			obj, err := parseAckRole(sourceFile, doc, root)
			return obj, "", err
		case "Policy":
			obj, err := parseAckPolicy(sourceFile, doc, root)
			return obj, "", err
		default:
			return nil, fmt.Sprintf("unrecognized %s kind: %s", ackAPIGroupPrefix, kindStr), nil
		}

	case looksLikePolicyDocument(doc):
		obj, err := parseRawPolicy(sourceFile, doc, root)
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

func parseRawPolicy(sourceFile string, doc map[string]any, root *yaml.Node) (*Object, error) {
	d, err := decodeDocument(doc)
	if err != nil {
		return nil, fmt.Errorf("decoding raw policy document: %w", err)
	}
	return &Object{
		SourceFile:       sourceFile,
		Kind:             KindRawPolicy,
		Document:         &d,
		Line:             root.Line,
		DocumentLocation: PolicyLocation{Line: root.Line, StatementLines: statementLines(root, 0)},
	}, nil
}

func parseAckPolicy(sourceFile string, doc map[string]any, root *yaml.Node) (*Object, error) {
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

		Line:             root.Line,
		DocumentLocation: embeddedLocation(mappingPath(root, "spec"), "policyDocument"),
	}, nil
}

func parseAckRole(sourceFile string, doc map[string]any, root *yaml.Node) (*Object, error) {
	spec, _ := doc["spec"].(map[string]any)
	name, _ := spec["name"].(string)
	specNode := mappingPath(root, "spec")

	obj := &Object{
		SourceFile:  sourceFile,
		Kind:        KindRole,
		Name:        name,
		Tags:        parseAckTags(spec["tags"]),
		Annotations: parseAckAnnotations(doc),

		Line:                     root.Line,
		AssumeRolePolicyLocation: embeddedLocation(specNode, "assumeRolePolicyDocument"),
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
		obj.InlinePolicyLocations = make(map[string]PolicyLocation, len(inline))
		inlineNode := mappingPath(specNode, "inlinePolicies")
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
			obj.InlinePolicyLocations[policyName] = embeddedLocation(inlineNode, policyName)
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

// mappingEntry returns the key and value nodes for key in mapping node m,
// or nils if m is not a mapping or has no such key.
func mappingEntry(m *yaml.Node, key string) (*yaml.Node, *yaml.Node) {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i], m.Content[i+1]
		}
	}
	return nil, nil
}

// mappingPath walks nested mapping keys from m, returning nil if any step
// is missing.
func mappingPath(m *yaml.Node, keys ...string) *yaml.Node {
	for _, k := range keys {
		_, m = mappingEntry(m, k)
	}
	return m
}

// statementLines returns the line of each Statement entry in policy
// document node m, shifted by offset. A single-object Statement (valid IAM
// grammar) counts as index 0.
func statementLines(m *yaml.Node, offset int) []int {
	_, stmt := mappingEntry(m, "Statement")
	switch {
	case stmt == nil:
		return nil
	case stmt.Kind == yaml.SequenceNode:
		lines := make([]int, len(stmt.Content))
		for i, n := range stmt.Content {
			lines[i] = n.Line + offset
		}
		return lines
	default:
		return []int{stmt.Line + offset}
	}
}

// embeddedLocation locates a policy document embedded as a JSON string
// under key in mapping node parent (the ACK CRD shape).
func embeddedLocation(parent *yaml.Node, key string) PolicyLocation {
	k, v := mappingEntry(parent, key)
	if k == nil {
		return PolicyLocation{}
	}
	loc := PolicyLocation{Line: k.Line}
	if v.Style != yaml.LiteralStyle {
		return loc
	}
	// JSON is valid YAML, so the embedded string parses to a node tree with
	// lines relative to the string. A literal block's content starts on the
	// line after v, so inner line N sits at file line v.Line+N.
	var inner yaml.Node
	if err := yaml.Unmarshal([]byte(v.Value), &inner); err != nil || len(inner.Content) == 0 {
		return loc
	}
	loc.StatementLines = statementLines(inner.Content[0], v.Line)
	return loc
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

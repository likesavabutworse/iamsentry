// Package policy defines the normalized IAM policy document model shared by
// every input source (raw JSON, ACK CRDs) and every check layer (Access
// Analyzer, Rego).
package policy

import (
	"encoding/json"
	"fmt"
)

// Document is an IAM policy document (the "Version"/"Statement" JSON shape).
type Document struct {
	Version   string      `json:"Version,omitempty"`
	Id        string      `json:"Id,omitempty"`
	Statement []Statement `json:"Statement"`
}

// Statement is a single IAM policy statement. Action/Resource/NotAction/
// NotResource accept either a single string or an array in IAM's JSON grammar;
// StringOrSlice normalizes both to a slice on unmarshal.
type Statement struct {
	Sid          string         `json:"Sid,omitempty"`
	Effect       string         `json:"Effect"`
	Principal    any            `json:"Principal,omitempty"`
	NotPrincipal any            `json:"NotPrincipal,omitempty"`
	Action       StringOrSlice  `json:"Action,omitempty"`
	NotAction    StringOrSlice  `json:"NotAction,omitempty"`
	Resource     StringOrSlice  `json:"Resource,omitempty"`
	NotResource  StringOrSlice  `json:"NotResource,omitempty"`
	Condition    map[string]any `json:"Condition,omitempty"`
}

// StringOrSlice unmarshals an IAM grammar field that may be a JSON string or
// a JSON array of strings into a []string, and always marshals back out as
// an array (even a single element) — a single-element array is equivalent
// to a bare string in IAM's grammar, and every consumer of this package
// (the Rego input path and the Access Analyzer wrapper) needs a uniform
// shape, not one that depends on how many elements happen to be present.
type StringOrSlice []string

func (s *StringOrSlice) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		if single != "" {
			*s = []string{single}
		}
		return nil
	}
	var multi []string
	if err := json.Unmarshal(data, &multi); err != nil {
		return fmt.Errorf("action/resource field is neither a string nor an array of strings: %w", err)
	}
	*s = multi
	return nil
}

// ParseDocument parses a JSON-encoded IAM policy document string, as found in
// a raw policy file or embedded in an ACK CRD field (policyDocument,
// assumeRolePolicyDocument, one entry of inlinePolicies).
func ParseDocument(raw string) (Document, error) {
	var doc Document
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return Document{}, fmt.Errorf("parsing IAM policy document: %w", err)
	}
	return doc, nil
}

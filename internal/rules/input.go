package rules

import (
	"encoding/json"
	"fmt"

	"github.com/likesavabutworse/iamsentry/internal/input"
	"github.com/likesavabutworse/iamsentry/internal/policy"
)

// regoInput is the stable, documented shape every rule (built-in or
// user-supplied) sees as `input`. Field names here are the public contract
// for rule authors — see rules/examples/*.rego for usage.
type regoInput struct {
	Kind       string `json:"kind"`
	Name       string `json:"name,omitempty"`
	SourceFile string `json:"source_file"`
	// Tags is deliberately not omitempty: rules like
	// rules/examples/required_owner_tag.rego call object.get(input.tags, ...),
	// which is undefined (not "") when input.tags is absent — so an object
	// with no tags must still serialize as {} rather than dropping the key.
	Tags               map[string]string          `json:"tags"`
	Document           *policy.Document           `json:"document,omitempty"`
	AssumeRolePolicy   *policy.Document           `json:"assume_role_policy,omitempty"`
	InlinePolicies     map[string]policy.Document `json:"inline_policies,omitempty"`
	AttachedPolicyARNs []string                   `json:"attached_policy_arns,omitempty"`
}

// ToInput converts a scanned input.Object into the map[string]any shape
// Evaluate expects, via a JSON round-trip so Rego sees the same field names
// and types documented on regoInput.
func ToInput(obj input.Object) (map[string]any, error) {
	tags := obj.Tags
	if tags == nil {
		// A nil map marshals as JSON null, not {} — see the Tags field
		// comment on regoInput for why rules need it to always be an object.
		tags = map[string]string{}
	}
	ri := regoInput{
		Kind:               string(obj.Kind),
		Name:               obj.Name,
		SourceFile:         obj.SourceFile,
		Tags:               tags,
		Document:           obj.Document,
		AssumeRolePolicy:   obj.AssumeRolePolicy,
		InlinePolicies:     obj.InlinePolicies,
		AttachedPolicyARNs: obj.AttachedPolicyARNs,
	}
	b, err := json.Marshal(ri)
	if err != nil {
		return nil, fmt.Errorf("marshaling rego input: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("unmarshaling rego input: %w", err)
	}
	return m, nil
}

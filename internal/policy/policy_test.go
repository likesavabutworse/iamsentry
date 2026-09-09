package policy

import (
	"encoding/json"
	"testing"
)

// TestStringOrSlice_MarshalAlwaysArray guards a real bug: an earlier version
// of MarshalJSON collapsed a single-element StringOrSlice back to a bare
// JSON string, which silently broke `stmt.Action[_]` iteration in every
// Rego rule whenever a statement had exactly one action — the rules simply
// never fired, with no error anywhere in the pipeline.
func TestStringOrSlice_MarshalAlwaysArray(t *testing.T) {
	stmt := Statement{Effect: "Allow", Action: StringOrSlice{"iam:PutRolePolicy"}}
	b, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, ok := m["Action"].([]any); !ok {
		t.Errorf("Action marshaled as %T (%v), want a JSON array even for one element", m["Action"], m["Action"])
	}
}

func TestStringOrSlice_UnmarshalsBothShapes(t *testing.T) {
	var single Statement
	if err := json.Unmarshal([]byte(`{"Effect":"Allow","Action":"s3:GetObject"}`), &single); err != nil {
		t.Fatalf("Unmarshal single: %v", err)
	}
	if len(single.Action) != 1 || single.Action[0] != "s3:GetObject" {
		t.Errorf("single string form: Action = %v", single.Action)
	}

	var multi Statement
	if err := json.Unmarshal([]byte(`{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"]}`), &multi); err != nil {
		t.Fatalf("Unmarshal multi: %v", err)
	}
	if len(multi.Action) != 2 {
		t.Errorf("array form: Action = %v", multi.Action)
	}
}

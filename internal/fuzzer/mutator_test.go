package fuzzer

import (
	"testing"
)

func TestNewMutator(t *testing.T) {
	mutator := NewMutator([]MutationStrategy{BoundaryValues, TypeConfusion})
	if mutator == nil {
		t.Fatal("Expected mutator to be created")
	}

	if len(mutator.strategies) != 2 {
		t.Errorf("Expected 2 strategies, got %d", len(mutator.strategies))
	}
}

func TestMutateString(t *testing.T) {
	mutator := NewMutator([]MutationStrategy{BoundaryValues})
	mutations := mutator.Mutate("test", "string")

	if len(mutations) == 0 {
		t.Fatal("Expected mutations to be generated")
	}

	// Should include original value
	found := false
	for _, m := range mutations {
		if m == "test" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Original value not found in mutations")
	}
}

func TestMutateInteger(t *testing.T) {
	mutator := NewMutator([]MutationStrategy{BoundaryValues})
	mutations := mutator.Mutate(42, "integer")

	if len(mutations) == 0 {
		t.Fatal("Expected mutations to be generated")
	}

	// Should include boundary values
	boundaries := []interface{}{0, -1, 1}
	for _, boundary := range boundaries {
		found := false
		for _, m := range mutations {
			if m == boundary {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Boundary value %v not found in mutations", boundary)
		}
	}
}

func TestInferType(t *testing.T) {
	mutator := NewMutator(nil)

	tests := []struct {
		input    interface{}
		expected string
	}{
		{"string", "string"},
		{42, "integer"},
		{3.14, "number"},
		{true, "boolean"},
		{[]interface{}{}, "array"},
		{map[string]interface{}{}, "object"},
		{nil, "unknown"},
	}

	for _, test := range tests {
		result := mutator.inferType(test.input)
		if result != test.expected {
			t.Errorf("For input %v, expected type %s, got %s", test.input, test.expected, result)
		}
	}
}

func TestDeduplicate(t *testing.T) {
	mutator := NewMutator(nil)

	input := []interface{}{"a", "b", "a", "c", "b"}
	result := mutator.deduplicate(input)

	if len(result) != 3 {
		t.Errorf("Expected 3 unique values, got %d", len(result))
	}

	// Check all unique values are present
	expected := []interface{}{"a", "b", "c"}
	for _, exp := range expected {
		found := false
		for _, r := range result {
			if r == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected value %v not found in deduplicated result", exp)
		}
	}
}

package executor

import (
	"testing"
)

// TestResolvePayloads verifies that raw interface{} payload maps are correctly
// converted to map[string][]string regardless of the underlying value type.
func TestResolvePayloads(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input map[string]interface{}
		want  map[string][]string
	}{
		{
			name: "handles []string value",
			input: map[string]interface{}{
				"username": []string{"admin", "root"},
			},
			want: map[string][]string{
				"username": {"admin", "root"},
			},
		},
		{
			name: "handles []interface{} value",
			input: map[string]interface{}{
				"password": []interface{}{"pass1", "pass2", "pass3"},
			},
			want: map[string][]string{
				"password": {"pass1", "pass2", "pass3"},
			},
		},
		{
			name: "handles single string value",
			input: map[string]interface{}{
				"token": "abc123",
			},
			want: map[string][]string{
				"token": {"abc123"},
			},
		},
		{
			name: "handles unsupported type as empty slice",
			input: map[string]interface{}{
				"num": 42,
			},
			want: map[string][]string{
				"num": {},
			},
		},
		{
			name: "handles multiple keys of mixed types",
			input: map[string]interface{}{
				"a": []string{"x"},
				"b": []interface{}{"y", "z"},
				"c": "single",
			},
			want: map[string][]string{
				"a": {"x"},
				"b": {"y", "z"},
				"c": {"single"},
			},
		},
		{
			name:  "handles nil / empty map",
			input: map[string]interface{}{},
			want:  map[string][]string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := ResolvePayloads(tc.input)

			if len(got) != len(tc.want) {
				t.Fatalf("got %d keys, want %d", len(got), len(tc.want))
			}

			for k, wantVals := range tc.want {
				gotVals, ok := got[k]
				if !ok {
					t.Errorf("missing key %q in result", k)
					continue
				}
				if len(gotVals) != len(wantVals) {
					t.Errorf("key %q: got %v, want %v", k, gotVals, wantVals)
					continue
				}
				for i, wv := range wantVals {
					if gotVals[i] != wv {
						t.Errorf("key %q[%d]: got %q, want %q", k, i, gotVals[i], wv)
					}
				}
			}
		})
	}
}

// TestGeneratePayloadCombinations_Batteringram verifies that batteringram mode
// applies each value from the first payload set to ALL keys.
func TestGeneratePayloadCombinations_Batteringram(t *testing.T) {
	t.Parallel()

	payloads := map[string][]string{
		"user": {"admin", "root", "guest"},
		"pass": {"admin", "root", "guest"}, // same set size; values don't matter for batteringram
	}

	combos := GeneratePayloadCombinations(payloads, "batteringram")

	if len(combos) != 3 {
		t.Fatalf("expected 3 combos, got %d", len(combos))
	}

	// Batteringram iterates first payload set (sorted: "pass") and applies to all keys.
	firstKey := "pass" // alphabetically first
	firstSet := payloads[firstKey]

	for i, combo := range combos {
		expectedVal := firstSet[i]
		for k := range payloads {
			if combo[k] != expectedVal {
				t.Errorf("combo[%d][%q] = %q, want %q", i, k, combo[k], expectedVal)
			}
		}
	}
}

// TestGeneratePayloadCombinations_Batteringram_SingleKey verifies batteringram with
// a single payload key produces one combo per payload value.
func TestGeneratePayloadCombinations_Batteringram_SingleKey(t *testing.T) {
	t.Parallel()

	payloads := map[string][]string{
		"payload": {"a", "b", "c"},
	}

	combos := GeneratePayloadCombinations(payloads, "batteringram")

	if len(combos) != 3 {
		t.Fatalf("expected 3 combos, got %d", len(combos))
	}

	expected := []string{"a", "b", "c"}
	for i, combo := range combos {
		if combo["payload"] != expected[i] {
			t.Errorf("combo[%d][payload] = %q, want %q", i, combo["payload"], expected[i])
		}
	}
}

// TestGeneratePayloadCombinations_Pitchfork verifies that pitchfork mode pairs
// payloads by index and produces min(len) combinations.
func TestGeneratePayloadCombinations_Pitchfork(t *testing.T) {
	t.Parallel()

	payloads := map[string][]string{
		"user": {"admin", "root", "guest"},
		"pass": {"secret", "toor", "hunter2"},
	}

	combos := GeneratePayloadCombinations(payloads, "pitchfork")

	if len(combos) != 3 {
		t.Fatalf("expected 3 combos, got %d", len(combos))
	}

	// Keys sorted: "pass", "user"
	wantPass := []string{"secret", "toor", "hunter2"}
	wantUser := []string{"admin", "root", "guest"}

	for i, combo := range combos {
		if combo["pass"] != wantPass[i] {
			t.Errorf("combo[%d][pass] = %q, want %q", i, combo["pass"], wantPass[i])
		}
		if combo["user"] != wantUser[i] {
			t.Errorf("combo[%d][user] = %q, want %q", i, combo["user"], wantUser[i])
		}
	}
}

// TestGeneratePayloadCombinations_Pitchfork_MinLength verifies that pitchfork stops
// at the shortest payload set.
func TestGeneratePayloadCombinations_Pitchfork_MinLength(t *testing.T) {
	t.Parallel()

	payloads := map[string][]string{
		"a": {"1", "2", "3", "4"},
		"b": {"x", "y"},
	}

	combos := GeneratePayloadCombinations(payloads, "pitchfork")

	if len(combos) != 2 {
		t.Fatalf("expected 2 combos (min length), got %d", len(combos))
	}
}

// TestGeneratePayloadCombinations_Clusterbomb verifies that clusterbomb mode
// produces the cartesian product of all payload sets.
func TestGeneratePayloadCombinations_Clusterbomb(t *testing.T) {
	t.Parallel()

	payloads := map[string][]string{
		"user": {"admin", "root"},
		"pass": {"secret", "hunter2"},
	}

	combos := GeneratePayloadCombinations(payloads, "clusterbomb")

	// 2 × 2 = 4 combinations.
	if len(combos) != 4 {
		t.Fatalf("expected 4 combos, got %d", len(combos))
	}

	// Verify all combinations are present using a set.
	type pair struct{ user, pass string }

	seen := make(map[pair]bool, 4)
	for _, c := range combos {
		seen[pair{c["user"], c["pass"]}] = true
	}

	expected := []pair{
		{"admin", "secret"},
		{"admin", "hunter2"},
		{"root", "secret"},
		{"root", "hunter2"},
	}

	for _, e := range expected {
		if !seen[e] {
			t.Errorf("missing combination user=%q pass=%q", e.user, e.pass)
		}
	}
}

// TestGeneratePayloadCombinations_Clusterbomb_ThreeSets verifies that clusterbomb
// correctly computes the cartesian product for three payload sets.
func TestGeneratePayloadCombinations_Clusterbomb_ThreeSets(t *testing.T) {
	t.Parallel()

	payloads := map[string][]string{
		"a": {"1", "2"},
		"b": {"x", "y"},
		"c": {"p", "q"},
	}

	combos := GeneratePayloadCombinations(payloads, "clusterbomb")

	// 2 × 2 × 2 = 8 combinations.
	if len(combos) != 8 {
		t.Fatalf("expected 8 combos, got %d", len(combos))
	}
}

// TestGeneratePayloadCombinations_EmptyPayloads verifies that empty input returns nil.
func TestGeneratePayloadCombinations_EmptyPayloads(t *testing.T) {
	t.Parallel()

	for _, attackType := range []string{"batteringram", "pitchfork", "clusterbomb"} {
		combos := GeneratePayloadCombinations(map[string][]string{}, attackType)
		if combos != nil {
			t.Errorf("attack=%q: expected nil for empty payloads, got %v", attackType, combos)
		}
	}
}

// TestGeneratePayloadCombinations_DefaultAttackType verifies that an unrecognised
// attack type falls back to batteringram behaviour.
func TestGeneratePayloadCombinations_DefaultAttackType(t *testing.T) {
	t.Parallel()

	payloads := map[string][]string{
		"key": {"a", "b"},
	}

	combos := GeneratePayloadCombinations(payloads, "unknown")

	if len(combos) != 2 {
		t.Fatalf("expected 2 combos (batteringram default), got %d", len(combos))
	}
}

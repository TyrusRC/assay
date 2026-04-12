package executor

import "sort"

// ResolvePayloads converts raw payload map (interface{}) to string slices.
// It handles values that may be []interface{}, []string, or a single string.
func ResolvePayloads(raw map[string]interface{}) map[string][]string {
	resolved := make(map[string][]string, len(raw))

	for key, val := range raw {
		switch v := val.(type) {
		case []string:
			resolved[key] = v
		case []interface{}:
			strs := make([]string, 0, len(v))
			for _, item := range v {
				if s, ok := item.(string); ok {
					strs = append(strs, s)
				}
			}
			resolved[key] = strs
		case string:
			resolved[key] = []string{v}
		default:
			resolved[key] = []string{}
		}
	}

	return resolved
}

// GeneratePayloadCombinations generates payload combinations based on attack type.
// Supported attack types:
//   - batteringram: same payload value applied to ALL keys
//   - pitchfork: parallel iteration, position N gets payload N; length = min of all sets
//   - clusterbomb: cartesian product of all payload sets
//
// Keys are sorted for deterministic output.
func GeneratePayloadCombinations(payloads map[string][]string, attackType string) []map[string]string {
	if len(payloads) == 0 {
		return nil
	}

	// Build sorted key list for deterministic ordering.
	keys := make([]string, 0, len(payloads))
	for k := range payloads {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	switch attackType {
	case "pitchfork":
		return generatePitchfork(payloads, keys)
	case "clusterbomb":
		return generateClusterbomb(payloads, keys)
	default:
		// batteringram is the default behaviour.
		return generateBatteringram(payloads, keys)
	}
}

// generateBatteringram iterates over the first payload set and applies each
// value to ALL keys simultaneously.
func generateBatteringram(payloads map[string][]string, keys []string) []map[string]string {
	if len(keys) == 0 {
		return nil
	}

	firstKey := keys[0]
	firstSet := payloads[firstKey]

	combos := make([]map[string]string, 0, len(firstSet))

	for _, val := range firstSet {
		combo := make(map[string]string, len(keys))
		for _, k := range keys {
			combo[k] = val
		}
		combos = append(combos, combo)
	}

	return combos
}

// generatePitchfork pairs payloads by index across all sets.
// The number of combinations equals the length of the shortest set.
func generatePitchfork(payloads map[string][]string, keys []string) []map[string]string {
	if len(keys) == 0 {
		return nil
	}

	// Find minimum length across all sets.
	minLen := len(payloads[keys[0]])
	for _, k := range keys[1:] {
		if l := len(payloads[k]); l < minLen {
			minLen = l
		}
	}

	combos := make([]map[string]string, 0, minLen)

	for i := range minLen {
		combo := make(map[string]string, len(keys))
		for _, k := range keys {
			combo[k] = payloads[k][i]
		}
		combos = append(combos, combo)
	}

	return combos
}

// generateClusterbomb produces the cartesian product of all payload sets.
func generateClusterbomb(payloads map[string][]string, keys []string) []map[string]string {
	if len(keys) == 0 {
		return nil
	}

	// Seed with an empty combination.
	combos := []map[string]string{{}}

	for _, k := range keys {
		vals := payloads[k]
		expanded := make([]map[string]string, 0, len(combos)*len(vals))

		for _, existing := range combos {
			for _, v := range vals {
				next := make(map[string]string, len(existing)+1)
				for ek, ev := range existing {
					next[ek] = ev
				}
				next[k] = v
				expanded = append(expanded, next)
			}
		}

		combos = expanded
	}

	// Remove the initial empty seed if no keys were processed.
	if len(combos) == 1 && len(combos[0]) == 0 {
		return nil
	}

	return combos
}

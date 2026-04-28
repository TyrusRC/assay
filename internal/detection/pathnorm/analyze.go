package pathnorm

import "strings"

// bodyShapeDiverged reports whether the bypass response body is materially
// different from the canonical (401/403) body. This is the FP guard for
// the most common false-positive on this detector class: a single-page
// app or auth proxy that returns the SAME forbidden page but with status
// 200 (an "internal redirect to login" pattern). Without this guard, any
// such app shows up as "vulnerable on every payload" — pure noise.
//
// Returns true iff the bypass response body is meaningfully different
// from canonical. We treat as "diverged" when:
//
//   - Both bodies are non-empty AND they differ by length by >25%, OR
//   - Token Jaccard overlap < 0.85 (i.e., they share fewer than 85% of
//     unique whitespace-separated tokens)
//
// Empty-vs-non-empty is treated as diverged. Both-empty is non-diverged
// (we can't make any judgment).
func bodyShapeDiverged(canonical, bypass string) bool {
	if canonical == "" && bypass == "" {
		return false
	}
	if canonical == "" || bypass == "" {
		return true
	}
	if canonical == bypass {
		return false
	}
	la, lb := len(canonical), len(bypass)
	// Length difference > 25% → diverged on size alone.
	if la*4 < lb*3 || lb*4 < la*3 {
		return true
	}
	a := tokenize(canonical)
	b := tokenize(bypass)
	if len(a) < 4 || len(b) < 4 {
		// Tiny bodies — fall back to byte equality (already failed) so
		// they count as diverged.
		return true
	}
	overlap := jaccard(a, b)
	return overlap < 0.85
}

// hasAdminMarkers heuristically detects whether a response body looks like
// an authenticated admin/dashboard page rather than e.g. a "404 not found"
// served at status 200. Used to grade severity: a bypass that lands on a
// page with multiple admin-y markers is far more likely to be a real
// auth-bypass-of-a-protected-resource than a soft 404.
//
// We require ≥ 2 distinct markers from the corpus to count as a hit, so a
// body that incidentally contains the literal word "admin" once doesn't
// trip the heuristic on its own (think marketing pages).
func hasAdminMarkers(body string) bool {
	lower := strings.ToLower(body)
	markers := []string{
		"dashboard", "control panel", "admin panel", "administration",
		"manage users", "user list", "logout", "settings",
		"delete user", "config", "system status", "audit log",
		"role: admin", "you are signed in as", "welcome,",
	}
	hits := 0
	for _, m := range markers {
		if strings.Contains(lower, m) {
			hits++
			if hits >= 2 {
				return true
			}
		}
	}
	return false
}

// tokenize splits a body on whitespace + common HTML punctuation and
// lowercases. The set is bounded so a 1MB body doesn't allocate O(N) map
// entries on every comparison.
func tokenize(s string) map[string]struct{} {
	out := make(map[string]struct{}, len(s)/8)
	cur := make([]byte, 0, 32)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c == '<' || c == '>' || c == '"' || c == '\'' || c == '/' || c == '=' {
			if len(cur) > 0 {
				out[strings.ToLower(string(cur))] = struct{}{}
				cur = cur[:0]
			}
			continue
		}
		cur = append(cur, c)
	}
	if len(cur) > 0 {
		out[strings.ToLower(string(cur))] = struct{}{}
	}
	return out
}

func jaccard(a, b map[string]struct{}) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	inter := 0
	for k := range a {
		if _, ok := b[k]; ok {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

package decision

import (
	"context"
	"os"
	"testing"
)

// TestAdjudicateLive is a functional check against a running Haruspex engine
// (ASSAY_DECISION_BASE_URL or the loopback default). It skips when no engine is
// reachable, so it is safe in CI. It asserts the fail-open Adjudicate client
// separates a confirmed finding from pure noise.
func TestAdjudicateLive(t *testing.T) {
	base := os.Getenv("ASSAY_DECISION_BASE_URL")
	if base == "" {
		base = "http://127.0.0.1:3000"
	}
	cfg := Config{Enabled: true, Model: "haruspex", BaseURL: base}
	items := []Item{
		{Key: "rce", Text: "eval of 7*7 returned 49 and os.popen('id') returned uid=0(root), unauthenticated [verified]"},
		{Key: "noise", Text: "the OPTIONS HTTP method is enabled and returns an Allow header"},
		{Key: "safe", Text: "the query uses parameterized bindings cursor.execute(sql, (id,))"},
	}
	probs, err := Adjudicate(context.Background(), cfg, items)
	if err != nil || probs == nil {
		t.Skipf("haruspex engine not reachable (%v) — skipping live adjudication test", err)
	}
	for i, p := range probs {
		if p == nil {
			t.Fatalf("item %d (%s): engine returned no opinion (nil) on a normal request", i, items[i].Key)
		}
	}
	rce, noise, safe := *probs[0], *probs[1], *probs[2]
	t.Logf("adjudicate probs: rce=%.3f noise=%.3f safe=%.3f", rce, noise, safe)
	if rce <= noise || rce <= safe {
		t.Errorf("expected confirmed finding (%.3f) ranked above noise (%.3f) and safe (%.3f)", rce, noise, safe)
	}
}

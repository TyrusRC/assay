package domdetect

import (
	"context"
	"strings"
	"testing"
)

func TestDetectProtoPollution_BracketShape(t *testing.T) {
	// Simulate an app whose URL parser merges bracket-syntax keys into
	// Object.prototype: `?__proto__[skwsPP<X>]=POLLUTED` causes the
	// browser-side eval `({})[<sentinel>]` to return "POLLUTED".
	runner := &fakeRunner{
		evalHandler: func(visited, expr string) string {
			// The detector embeds the sentinel literally in the URL via
			// `__proto__[skwsPP<hex>]=POLLUTED`. We parse the visited
			// URL's raw query and confirm both the key and value are
			// present, then emit POLLUTED to mimic a real polluted
			// prototype.
			if !strings.Contains(visited, "__proto__%5B") &&
				!strings.Contains(visited, "__proto__[") {
				return ""
			}
			if !strings.Contains(visited, "POLLUTED") {
				return ""
			}
			// The eval expression is `(({})["<sentinel>"]) || ""`.
			// Return POLLUTED to satisfy the contract.
			if strings.Contains(expr, "skwsPP") {
				return "POLLUTED"
			}
			return ""
		},
	}

	res, err := DetectProtoPollution(context.Background(), runner, "http://app.test/blog")
	if err != nil {
		t.Fatalf("DetectProtoPollution error: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatalf("expected proto-pollution finding, got 0; visited=%v", runner.visited)
	}
	if !strings.Contains(strings.ToLower(res.Findings[0].Type), "prototype") {
		t.Errorf("expected prototype-pollution-typed finding, got Type=%q", res.Findings[0].Type)
	}
}

func TestDetectProtoPollution_NotVulnerable(t *testing.T) {
	runner := &fakeRunner{
		evalHandler: func(_, _ string) string { return "" },
	}
	res, err := DetectProtoPollution(context.Background(), runner, "http://app.test/blog")
	if err != nil {
		t.Fatalf("DetectProtoPollution error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(res.Findings))
	}
}

func TestDetectProtoPollution_NilRunner(t *testing.T) {
	res, err := DetectProtoPollution(context.Background(), nil, "http://app.test/blog")
	if err != nil {
		t.Fatalf("nil runner should not error, got %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected empty result with nil runner, got %d findings", len(res.Findings))
	}
}

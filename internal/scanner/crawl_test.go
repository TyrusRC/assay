package scanner

import (
	"context"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
)

func mustTarget(t *testing.T, raw string) *core.Target {
	t.Helper()
	tgt, err := core.NewTarget(raw)
	if err != nil {
		t.Fatalf("NewTarget(%q): %v", raw, err)
	}
	return tgt
}

func TestMergeDiscoveredTargets(t *testing.T) {
	seeds := []*core.Target{mustTarget(t, "https://example.com/")}

	tests := []struct {
		name       string
		discovered []string
		wantCount  int
	}{
		{"no discoveries keeps seeds", nil, 1},
		{"appends new urls", []string{"https://example.com/a", "https://example.com/b"}, 3},
		{"dedupes against seed", []string{"https://example.com/", "https://example.com/a"}, 2},
		{"dedupes within discovered", []string{"https://example.com/a", "https://example.com/a"}, 2},
		{"skips invalid urls", []string{"://not-a-url", "https://example.com/a"}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeDiscoveredTargets(seeds, tt.discovered)
			if len(got) != tt.wantCount {
				t.Errorf("merged count = %d, want %d (%v)", len(got), tt.wantCount, urls(got))
			}
			if got[0].URL() != "https://example.com/" {
				t.Errorf("seed must come first, got %q", got[0].URL())
			}
		})
	}
}

func urls(ts []*core.Target) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.URL()
	}
	return out
}

func TestCrawlURLs_DisabledIsNoOp(t *testing.T) {
	// No headless pool and crawl disabled: must return (nil, nil), not panic.
	s := &InternalScanner{config: &InternalScanConfig{EnableSPACrawl: false}}
	got, err := s.CrawlURLs(context.Background(), "https://example.com/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil URLs when crawl disabled, got %v", got)
	}

	// Enabled but no pool (no Chrome) still degrades to a no-op.
	s.config.EnableSPACrawl = true
	got, err = s.CrawlURLs(context.Background(), "https://example.com/")
	if err != nil {
		t.Fatalf("unexpected error with nil pool: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil URLs when no pool, got %v", got)
	}
}

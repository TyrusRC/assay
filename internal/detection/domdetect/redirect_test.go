package domdetect

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

func TestDetectDOMRedirect_VulnerableSink(t *testing.T) {
	// Simulate a client-side redirect sink: when any of the common
	// redirect-param names carries a `https://evil.example/` value, JS
	// assigns it to window.location, and `location.host` becomes evil.example.
	const baselineHost = "app.test"
	runner := &fakeRunner{
		evalHandler: func(visited, _ string) string {
			parsed, err := url.Parse(visited)
			if err != nil {
				return baselineHost
			}
			for _, k := range commonRedirectParams {
				if v := parsed.Query().Get(k); strings.Contains(v, evilDomain) {
					return evilDomain
				}
			}
			return baselineHost
		},
	}

	res, err := DetectDOMRedirect(context.Background(), runner, "http://app.test/blog/post?postId=1")
	if err != nil {
		t.Fatalf("DetectDOMRedirect error: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatalf("expected redirect finding, got 0; visited=%v", runner.visited)
	}
	if !strings.Contains(strings.ToLower(res.Findings[0].Type), "redirect") {
		t.Errorf("expected redirect-typed finding, got Type=%q", res.Findings[0].Type)
	}
}

func TestDetectDOMRedirect_StableHostNoFinding(t *testing.T) {
	// Server keeps location.host stable regardless of param — no DOM-based
	// redirect.
	runner := &fakeRunner{
		evalHandler: func(_, _ string) string { return "app.test" },
	}
	res, err := DetectDOMRedirect(context.Background(), runner, "http://app.test/blog?postId=1")
	if err != nil {
		t.Fatalf("DetectDOMRedirect error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on stable host, got %d", len(res.Findings))
	}
}

func TestDetectDOMRedirect_NilRunner(t *testing.T) {
	res, err := DetectDOMRedirect(context.Background(), nil, "http://app.test/blog")
	if err != nil {
		t.Fatalf("nil runner should not error, got %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected empty result with nil runner, got %d findings", len(res.Findings))
	}
}

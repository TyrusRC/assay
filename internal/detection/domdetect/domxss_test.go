package domdetect

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

// fakeRunner is a scripted Runner used by the domdetect tests. It records
// every URL the detector tried to Navigate to, and returns canned
// responses to EvalJS based on the most recent URL.
type fakeRunner struct {
	visited     []string
	evalHandler func(lastURL, expr string) string
	navErr      error
}

func (f *fakeRunner) Navigate(_ context.Context, u string) error {
	if f.navErr != nil {
		return f.navErr
	}
	f.visited = append(f.visited, u)
	return nil
}

func (f *fakeRunner) EvalJS(_ context.Context, expr string) (string, error) {
	if f.evalHandler == nil {
		return "", nil
	}
	last := ""
	if len(f.visited) > 0 {
		last = f.visited[len(f.visited)-1]
	}
	return f.evalHandler(last, expr), nil
}

func TestDetectXSS_ParamReachesJSSink(t *testing.T) {
	// Simulate a DOM XSS sink: the test app reads ?postId from query and
	// inserts it into innerHTML. Our payload contains `onerror=window[X]='HIT'`,
	// so when the runner "executes" it, we set the sentinel on window.
	runner := &fakeRunner{
		evalHandler: func(visited, expr string) string {
			// Extract the postId value (URL-decoded) and check whether it
			// contains a `window.<sentinel>='HIT'` assignment.
			parsed, err := url.Parse(visited)
			if err != nil {
				return ""
			}
			postID := parsed.Query().Get("postId")
			// Mimic a JS sink that inserts postID into the DOM and triggers
			// onerror handlers. If the payload sets window.skwsDomXss<X>,
			// we need to honor that assignment when EvalJS asks for it.
			if !strings.Contains(postID, "onerror=") {
				return ""
			}
			// Pull the sentinel name out of `window.<name>='HIT'`.
			start := strings.Index(postID, "window.")
			if start < 0 {
				return ""
			}
			rest := postID[start+len("window."):]
			end := strings.Index(rest, "=")
			if end < 0 {
				return ""
			}
			sentinelName := rest[:end]
			// EvalJS query is `window.<sentinel> || ""`. If the requested
			// sentinel matches what the payload "set", emit HIT.
			if strings.Contains(expr, sentinelName) {
				return "HIT"
			}
			return ""
		},
	}

	target := "http://app.test/blog/post?postId=1"
	res, err := DetectXSS(context.Background(), runner, target)
	if err != nil {
		t.Fatalf("DetectXSS error: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatalf("expected DOM XSS finding, got 0; visited=%v", runner.visited)
	}
	if res.Findings[0].Parameter != "postId" {
		t.Errorf("expected finding on postId, got %q", res.Findings[0].Parameter)
	}
	if !strings.Contains(strings.ToLower(res.Findings[0].Type), "xss") {
		t.Errorf("expected XSS-typed finding, got Type=%q", res.Findings[0].Type)
	}
}

func TestDetectXSS_NoSinkNoFinding(t *testing.T) {
	runner := &fakeRunner{
		evalHandler: func(_, _ string) string { return "" },
	}
	res, err := DetectXSS(context.Background(), runner, "http://app.test/?q=hi")
	if err != nil {
		t.Fatalf("DetectXSS error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on non-vuln server, got %d", len(res.Findings))
	}
}

func TestDetectXSS_NoParamsNoProbe(t *testing.T) {
	runner := &fakeRunner{}
	res, err := DetectXSS(context.Background(), runner, "http://app.test/blog")
	if err != nil {
		t.Fatalf("DetectXSS error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on parameter-free URL, got %d", len(res.Findings))
	}
	if len(runner.visited) != 0 {
		t.Errorf("expected no Navigate calls when URL has no params, got %d", len(runner.visited))
	}
}

func TestDetectXSS_NilRunner(t *testing.T) {
	res, err := DetectXSS(context.Background(), nil, "http://app.test/?x=1")
	if err != nil {
		t.Fatalf("nil runner should not error, got %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected empty result with nil runner, got %d findings", len(res.Findings))
	}
}

package dalfox

import (
	"strings"
	"testing"

	"github.com/TyrusRC/assay/internal/tools"
)

func TestBuildArgs(t *testing.T) {
	d := &Dalfox{binaryPath: "/usr/bin/dalfox", options: defaultOptions()}
	req := tools.NewToolRequest("http://example.com/?q=test")
	req.WithProxy("http://127.0.0.1:8080").WithCookies("session=abc")

	args := d.BuildArgs(req)
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "url http://example.com/?q=test") {
		t.Error("missing target URL in args")
	}
	if !strings.Contains(joined, "--proxy http://127.0.0.1:8080") {
		t.Error("missing proxy in args")
	}
	if !strings.Contains(joined, "--cookie session=abc") {
		t.Error("missing cookie in args")
	}
	if !strings.Contains(joined, "--silence") {
		t.Error("missing silence flag")
	}
	if !strings.Contains(joined, "--format json") {
		t.Error("missing json format")
	}
}

func TestParseOutput(t *testing.T) {
	d := &Dalfox{binaryPath: "/usr/bin/dalfox"}

	jsonLine := `{"type":"V","inject_type":"v","poc":"http://example.com/?q=%3Cscript%3Ealert(1)%3C/script%3E","param":"q","severity":"high","cwe":"CWE-79"}`
	result := d.ParseOutput(jsonLine, "http://example.com/?q=test")

	if !result.HasFindings() {
		t.Fatal("expected findings from verified XSS output")
	}
	if result.Findings[0].Parameter != "q" {
		t.Errorf("expected param q, got %s", result.Findings[0].Parameter)
	}
}

func TestParseOutputEmpty(t *testing.T) {
	d := &Dalfox{binaryPath: "/usr/bin/dalfox"}
	result := d.ParseOutput("", "http://example.com")
	if result.HasFindings() {
		t.Error("expected no findings from empty output")
	}
}

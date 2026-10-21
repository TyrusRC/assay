package commix

import (
	"strings"
	"testing"

	"github.com/TyrusRC/assay/internal/tools"
)

func TestBuildArgs(t *testing.T) {
	c := &Commix{binaryPath: "/usr/bin/commix", options: defaultOptions()}
	req := tools.NewToolRequest("http://example.com/?cmd=test")
	req.WithProxy("http://127.0.0.1:8080")

	args := c.BuildArgs(req)
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "--url=http://example.com/?cmd=test") {
		t.Error("missing target URL")
	}
	if !strings.Contains(joined, "--batch") {
		t.Error("missing batch flag")
	}
}

func TestBuildArgsBlockedFlag(t *testing.T) {
	c := &Commix{binaryPath: "/usr/bin/commix", options: defaultOptions()}
	req := tools.NewToolRequest("http://example.com/?cmd=test")
	req.WithCustomArgs("--os-cmd=whoami")

	args := c.BuildArgs(req)
	if args != nil {
		t.Error("expected nil args for blocked flag")
	}
}

func TestParseOutput(t *testing.T) {
	c := &Commix{binaryPath: "/usr/bin/commix"}

	output := `The GET parameter 'cmd' is injectable via results-based command injection technique.`
	result := c.ParseOutput(output, "http://example.com/?cmd=test")
	if !result.HasFindings() {
		t.Fatal("expected findings from injectable output")
	}
	if result.Findings[0].Parameter != "cmd" {
		t.Errorf("expected param cmd, got %s", result.Findings[0].Parameter)
	}
}

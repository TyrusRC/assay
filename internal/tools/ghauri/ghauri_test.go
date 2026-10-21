package ghauri

import (
	"strings"
	"testing"

	"github.com/TyrusRC/assay/internal/tools"
)

func TestBuildArgs(t *testing.T) {
	g := &Ghauri{binaryPath: "/usr/bin/ghauri", options: defaultOptions()}
	req := tools.NewToolRequest("http://example.com/?id=1")
	req.WithProxy("http://127.0.0.1:8080")

	args := g.BuildArgs(req)
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "-u http://example.com/?id=1") {
		t.Error("missing target URL")
	}
	if !strings.Contains(joined, "--batch") {
		t.Error("missing batch flag")
	}
	if !strings.Contains(joined, "--proxy http://127.0.0.1:8080") {
		t.Error("missing proxy")
	}
}

func TestBuildArgsBlockedFlag(t *testing.T) {
	g := &Ghauri{binaryPath: "/usr/bin/ghauri", options: defaultOptions()}
	req := tools.NewToolRequest("http://example.com/?id=1")
	req.WithCustomArgs("--os-shell")

	args := g.BuildArgs(req)
	if args != nil {
		t.Error("expected nil args for blocked flag")
	}
}

func TestParseOutput(t *testing.T) {
	g := &Ghauri{binaryPath: "/usr/bin/ghauri"}

	output := `
Parameter: id (GET)
    Type: boolean-based blind
    Payload: id=1 AND 5*5=25

[INFO] the target URL is injectable
`
	result := g.ParseOutput(output, "http://example.com/?id=1")
	if !result.HasFindings() {
		t.Fatal("expected findings from injectable output")
	}
	if result.Findings[0].Parameter != "id" {
		t.Errorf("expected param id, got %s", result.Findings[0].Parameter)
	}
}

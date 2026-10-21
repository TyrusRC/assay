package tplmap

import (
	"strings"
	"testing"

	"github.com/TyrusRC/assay/internal/tools"
)

func TestBuildArgs(t *testing.T) {
	tp := &Tplmap{binaryPath: "/usr/bin/tplmap", options: defaultOptions()}
	req := tools.NewToolRequest("http://example.com/?name=test")

	args := tp.BuildArgs(req)
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "-u http://example.com/?name=test") {
		t.Error("missing target URL")
	}
}

func TestBuildArgsBlockedFlag(t *testing.T) {
	tp := &Tplmap{binaryPath: "/usr/bin/tplmap", options: defaultOptions()}
	req := tools.NewToolRequest("http://example.com/?name=test")
	req.WithCustomArgs("--os-shell")

	args := tp.BuildArgs(req)
	if args != nil {
		t.Error("expected nil args for blocked flag")
	}
}

func TestParseOutput(t *testing.T) {
	tp := &Tplmap{binaryPath: "/usr/bin/tplmap"}

	output := `Tplmap identified the following injection point with the Jinja2 engine in parameter 'name'.`
	result := tp.ParseOutput(output, "http://example.com/?name=test")
	if !result.HasFindings() {
		t.Fatal("expected findings from confirmed SSTI output")
	}
}

func TestParseOutputNegative(t *testing.T) {
	tp := &Tplmap{binaryPath: "/usr/bin/tplmap"}
	result := tp.ParseOutput("Nothing found.", "http://example.com")
	if result.HasFindings() {
		t.Error("expected no findings")
	}
}

package tplmap

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/tools"
)

// Options configures Tplmap execution parameters.
type Options struct {
	Level   int
	Timeout int
	Engine  string // Force a specific template engine
}

func defaultOptions() Options {
	return Options{Level: 1, Timeout: 30}
}

// Tplmap wraps the Tplmap SSTI scanner.
type Tplmap struct {
	binaryPath string
	version    string
	options    Options
}

// New creates a new Tplmap instance.
func New() *Tplmap {
	t := &Tplmap{options: defaultOptions()}
	t.findBinary()
	return t
}

func (t *Tplmap) findBinary() {
	if path, err := exec.LookPath("tplmap"); err == nil {
		t.binaryPath = path
		return
	}
	for _, path := range []string{
		"/usr/bin/tplmap",
		"/usr/local/bin/tplmap",
		"/opt/tplmap/tplmap.py",
	} {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			t.binaryPath = path
			return
		}
	}
}

func (t *Tplmap) Name() string      { return "tplmap" }
func (t *Tplmap) IsAvailable() bool { return t.binaryPath != "" }

func (t *Tplmap) Version() string {
	if t.version != "" {
		return t.version
	}
	if !t.IsAvailable() {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, t.binaryPath, "--version").CombinedOutput()
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`v?([0-9]+\.[0-9]+\.?[0-9]*)`)
	if m := re.FindStringSubmatch(string(out)); len(m) > 1 {
		t.version = m[1]
	}
	return t.version
}

func (t *Tplmap) HealthCheck() error {
	if !t.IsAvailable() {
		return fmt.Errorf("tplmap binary not found")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, t.binaryPath, "--version").Run()
}

// WithOptions sets custom options.
func (t *Tplmap) WithOptions(opts Options) *Tplmap {
	t.options = opts
	return t
}

// tplmapBlockedFlags prevents escalation to shell.
var tplmapBlockedFlags = []string{
	"--os-shell", "--os-cmd", "--reverse-shell", "--bind-shell",
	"--upload", "--download",
}

func isTplmapBlockedFlag(arg string) bool {
	a := strings.SplitN(arg, "=", 2)[0]
	for _, b := range tplmapBlockedFlags {
		if a == b {
			return true
		}
	}
	return false
}

// BuildArgs builds command line arguments. Tplmap is Python and may
// crash on IPv6 bracket notation, so the URL is normalized to IPv4.
func (t *Tplmap) BuildArgs(req *tools.ToolRequest) []string {
	target := tools.NormalizeURLForIPv4(req.Target)

	args := []string{
		"-u", target,
	}

	if req.Data != "" {
		args = append(args, "-d", req.Data)
	}
	if req.Cookies != "" {
		args = append(args, "--cookie", req.Cookies)
	}
	if req.Proxy != "" {
		args = append(args, "--proxy", tools.NormalizeURLForIPv4(req.Proxy))
	}
	for name, value := range req.Headers {
		args = append(args, "-H", fmt.Sprintf("%s: %s", name, value))
	}
	if t.options.Level > 0 {
		args = append(args, fmt.Sprintf("--level=%d", t.options.Level))
	}
	if t.options.Engine != "" {
		args = append(args, "-e", t.options.Engine)
	}

	for _, a := range tools.StripInternalFlags(req.CustomArgs) {
		if isTplmapBlockedFlag(a) {
			return nil
		}
		args = append(args, a)
	}
	return args
}

// Execute runs Tplmap against the target.
func (t *Tplmap) Execute(ctx context.Context, req *tools.ToolRequest) (*tools.ToolResult, error) {
	start := time.Now()
	result := tools.NewToolResult(t.Name())

	if !t.IsAvailable() {
		result.AddError("tplmap binary not found")
		return result, fmt.Errorf("tplmap not available")
	}

	args := t.BuildArgs(req)
	if args == nil {
		result.AddError("blocked flag in custom args")
		return result, fmt.Errorf("blocked flag")
	}

	cmd := exec.CommandContext(ctx, t.binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result.ExecutionTime = time.Since(start)
	result.RawOutput = stdout.String()

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			result.AddError("execution timeout exceeded")
			return result, ctx.Err()
		}
	}

	parsed := t.ParseOutput(result.RawOutput, req.Target)
	result.AddFindings(parsed.Findings)
	return result, nil
}

// ParseOutput parses Tplmap output for SSTI findings.
func (t *Tplmap) ParseOutput(output, target string) *tools.ToolResult {
	result := tools.NewToolResult(t.Name())

	confirmed := strings.Contains(output, "confirmed") ||
		strings.Contains(output, "Exploitable") ||
		strings.Contains(output, "Tplmap identified")

	if !confirmed {
		return result
	}

	engineRe := regexp.MustCompile(`(?i)(?:confirmed|identified|exploitable).*?(?:engine|template).*?['"]?(\w+)['"]?`)
	paramRe := regexp.MustCompile(`parameter '([^']+)'`)

	engine := "unknown"
	param := ""

	if m := engineRe.FindStringSubmatch(output); len(m) > 1 {
		engine = m[1]
	}
	if m := paramRe.FindStringSubmatch(output); len(m) > 1 {
		param = m[1]
	}

	f := core.NewFinding("Server-Side Template Injection", core.SeverityCritical)
	f.URL = target
	f.Parameter = param
	f.Description = fmt.Sprintf("SSTI confirmed in %s template engine, parameter '%s'", engine, param)
	f.Tool = t.Name()
	f.WithOWASPMapping(
		[]string{"WSTG-INPV-18"},
		[]string{"A05:2025"},
		[]string{"CWE-1336"},
	)
	result.AddFinding(f)

	return result
}

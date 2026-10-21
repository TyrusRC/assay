package ghauri

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

// Options configures Ghauri execution parameters.
type Options struct {
	Level     int
	Risk      int
	Threads   int
	Technique string // BEUST
	DBMS      string
	Timeout   int
	Retries   int
}

func defaultOptions() Options {
	return Options{
		Level:   1,
		Risk:    1,
		Threads: 1,
		Timeout: 30,
		Retries: 3,
	}
}

// Ghauri wraps the Ghauri SQL injection tool.
type Ghauri struct {
	binaryPath string
	version    string
	options    Options
}

// New creates a new Ghauri instance.
func New() *Ghauri {
	g := &Ghauri{options: defaultOptions()}
	g.findBinary()
	return g
}

func (g *Ghauri) findBinary() {
	if path, err := exec.LookPath("ghauri"); err == nil {
		g.binaryPath = path
		return
	}
	for _, path := range []string{
		"/usr/bin/ghauri",
		"/usr/local/bin/ghauri",
		"/opt/ghauri/ghauri.py",
	} {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			g.binaryPath = path
			return
		}
	}
}

func (g *Ghauri) Name() string      { return "ghauri" }
func (g *Ghauri) IsAvailable() bool { return g.binaryPath != "" }

func (g *Ghauri) Version() string {
	if g.version != "" {
		return g.version
	}
	if !g.IsAvailable() {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, g.binaryPath, "--version").Output()
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`([0-9]+\.[0-9]+\.?[0-9]*)`)
	if m := re.FindStringSubmatch(string(out)); len(m) > 1 {
		g.version = m[1]
	}
	return g.version
}

func (g *Ghauri) HealthCheck() error {
	if !g.IsAvailable() {
		return fmt.Errorf("ghauri binary not found")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, g.binaryPath, "--version").Run()
}

// WithOptions sets custom options.
func (g *Ghauri) WithOptions(opts Options) *Ghauri {
	g.options = opts
	return g
}

// ghauriBlockedFlags prevents escalation beyond detection.
var ghauriBlockedFlags = []string{
	"--os-shell", "--os-cmd", "--file-read", "--file-write",
	"--sql-shell", "--sql-query",
}

func isGhauriBlockedFlag(arg string) bool {
	a := strings.SplitN(arg, "=", 2)[0]
	for _, b := range ghauriBlockedFlags {
		if a == b {
			return true
		}
	}
	return false
}

// BuildArgs builds command line arguments.
func (g *Ghauri) BuildArgs(req *tools.ToolRequest) []string {
	args := []string{
		"-u", req.Target,
		"--batch",
		fmt.Sprintf("--level=%d", g.options.Level),
		fmt.Sprintf("--risk=%d", g.options.Risk),
		fmt.Sprintf("--threads=%d", g.options.Threads),
	}

	if req.Method != "" && req.Method != "GET" {
		args = append(args, "--method", req.Method)
	}
	if req.Data != "" {
		args = append(args, "--data", req.Data)
	}
	for name, value := range req.Headers {
		args = append(args, "-H", fmt.Sprintf("%s: %s", name, value))
	}
	if req.Cookies != "" {
		args = append(args, "--cookie", req.Cookies)
	}
	if req.Proxy != "" {
		args = append(args, "--proxy", req.Proxy)
	}
	if g.options.Technique != "" {
		args = append(args, "--technique", g.options.Technique)
	}
	if g.options.DBMS != "" {
		args = append(args, "--dbms", g.options.DBMS)
	}

	for _, a := range req.CustomArgs {
		if isGhauriBlockedFlag(a) {
			return nil
		}
		args = append(args, a)
	}
	return args
}

// Execute runs Ghauri against the target.
func (g *Ghauri) Execute(ctx context.Context, req *tools.ToolRequest) (*tools.ToolResult, error) {
	start := time.Now()
	result := tools.NewToolResult(g.Name())

	if !g.IsAvailable() {
		result.AddError("ghauri binary not found")
		return result, fmt.Errorf("ghauri not available")
	}

	args := g.BuildArgs(req)
	if args == nil {
		result.AddError("blocked flag in custom args")
		return result, fmt.Errorf("blocked flag")
	}

	cmd := exec.CommandContext(ctx, g.binaryPath, args...)
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
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() > 1 {
			result.AddError(fmt.Sprintf("ghauri exited with code %d: %s",
				exitErr.ExitCode(), stderr.String()))
		}
	}

	parsed := g.ParseOutput(result.RawOutput, req.Target)
	result.AddFindings(parsed.Findings)
	return result, nil
}

// ParseOutput parses Ghauri output for injection findings.
func (g *Ghauri) ParseOutput(output, target string) *tools.ToolResult {
	result := tools.NewToolResult(g.Name())

	if !strings.Contains(output, "injectable") &&
		!strings.Contains(output, "is vulnerable") {
		return result
	}

	findings := g.extractFindings(output, target)
	result.AddFindings(findings)
	return result
}

func (g *Ghauri) extractFindings(output, target string) []*core.Finding {
	var findings []*core.Finding

	paramRe := regexp.MustCompile(`Parameter:\s+(\S+)\s+\((\w+)\)`)
	typeRe := regexp.MustCompile(`Type:\s+(.+)`)
	payloadRe := regexp.MustCompile(`Payload:\s+(.+)`)

	lines := strings.Split(output, "\n")
	var curParam, curMethod string

	for i, line := range lines {
		if m := paramRe.FindStringSubmatch(line); len(m) > 2 {
			curParam = m[1]
			curMethod = m[2]
		}
		if m := typeRe.FindStringSubmatch(line); len(m) > 1 {
			injType := strings.TrimSpace(m[1])
			payload := ""
			for j := i + 1; j < len(lines) && j < i+5; j++ {
				if pm := payloadRe.FindStringSubmatch(lines[j]); len(pm) > 1 {
					payload = strings.TrimSpace(pm[1])
					break
				}
			}

			f := core.NewFinding("SQL Injection", g.determineSeverity(injType))
			f.URL = target
			f.Parameter = curParam
			f.Description = fmt.Sprintf("%s SQL Injection in %s parameter '%s'",
				injType, curMethod, curParam)
			f.Evidence = payload
			f.Tool = g.Name()
			f.WithOWASPMapping(
				[]string{"WSTG-INPV-05"},
				[]string{"A05:2025"},
				[]string{"CWE-89"},
			)
			findings = append(findings, f)
		}
	}

	if len(findings) == 0 && strings.Contains(output, "injectable") {
		f := core.NewFinding("SQL Injection", core.SeverityHigh)
		f.URL = target
		f.Description = "SQL Injection vulnerability detected"
		f.Tool = g.Name()
		f.WithOWASPMapping(
			[]string{"WSTG-INPV-05"},
			[]string{"A05:2025"},
			[]string{"CWE-89"},
		)
		findings = append(findings, f)
	}

	return findings
}

func (g *Ghauri) determineSeverity(injType string) core.Severity {
	lower := strings.ToLower(injType)
	if strings.Contains(lower, "union") || strings.Contains(lower, "stacked") {
		return core.SeverityCritical
	}
	if strings.Contains(lower, "error-based") {
		return core.SeverityCritical
	}
	return core.SeverityHigh
}

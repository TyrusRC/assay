package commix

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

// Options configures Commix execution parameters.
type Options struct {
	Level   int
	Timeout int
}

func defaultOptions() Options {
	return Options{Level: 1, Timeout: 30}
}

// Commix wraps the Commix command injection tool.
type Commix struct {
	binaryPath string
	version    string
	options    Options
}

// New creates a new Commix instance.
func New() *Commix {
	c := &Commix{options: defaultOptions()}
	c.findBinary()
	return c
}

func (c *Commix) findBinary() {
	if path, err := exec.LookPath("commix"); err == nil {
		c.binaryPath = path
		return
	}
	for _, path := range []string{
		"/usr/bin/commix",
		"/usr/local/bin/commix",
		"/opt/commix/commix.py",
	} {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			c.binaryPath = path
			return
		}
	}
}

func (c *Commix) Name() string      { return "commix" }
func (c *Commix) IsAvailable() bool { return c.binaryPath != "" }

func (c *Commix) Version() string {
	if c.version != "" {
		return c.version
	}
	if !c.IsAvailable() {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, c.binaryPath, "--version").Output()
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`v?([0-9]+\.[0-9]+[a-z0-9.-]*)`)
	if m := re.FindStringSubmatch(string(out)); len(m) > 1 {
		c.version = m[1]
	}
	return c.version
}

func (c *Commix) HealthCheck() error {
	if !c.IsAvailable() {
		return fmt.Errorf("commix binary not found")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, c.binaryPath, "--version").Run()
}

// WithOptions sets custom options.
func (c *Commix) WithOptions(opts Options) *Commix {
	c.options = opts
	return c
}

// commixBlockedFlags prevents escalation to shell access.
var commixBlockedFlags = []string{
	"--os-cmd", "--reverse-tcp", "--bind-tcp", "--file-write",
	"--file-upload", "--file-dest",
}

func isCommixBlockedFlag(arg string) bool {
	a := strings.SplitN(arg, "=", 2)[0]
	for _, b := range commixBlockedFlags {
		if a == b {
			return true
		}
	}
	return false
}

// BuildArgs builds command line arguments.
func (c *Commix) BuildArgs(req *tools.ToolRequest) []string {
	args := []string{
		fmt.Sprintf("--url=%s", req.Target),
		"--batch",
		fmt.Sprintf("--level=%d", c.options.Level),
	}

	if req.Data != "" {
		args = append(args, fmt.Sprintf("--data=%s", req.Data))
	}
	if req.Cookies != "" {
		args = append(args, fmt.Sprintf("--cookie=%s", req.Cookies))
	}
	if req.Proxy != "" {
		args = append(args, fmt.Sprintf("--proxy=%s", req.Proxy))
	}
	if req.OutputDir != "" {
		args = append(args, fmt.Sprintf("--output-dir=%s", req.OutputDir))
	}
	for name, value := range req.Headers {
		args = append(args, fmt.Sprintf("--header=%s: %s", name, value))
	}

	for _, a := range req.CustomArgs {
		if isCommixBlockedFlag(a) {
			return nil
		}
		args = append(args, a)
	}
	return args
}

// Execute runs Commix against the target.
func (c *Commix) Execute(ctx context.Context, req *tools.ToolRequest) (*tools.ToolResult, error) {
	start := time.Now()
	result := tools.NewToolResult(c.Name())

	if !c.IsAvailable() {
		result.AddError("commix binary not found")
		return result, fmt.Errorf("commix not available")
	}

	args := c.BuildArgs(req)
	if args == nil {
		result.AddError("blocked flag in custom args")
		return result, fmt.Errorf("blocked flag")
	}

	cmd := exec.CommandContext(ctx, c.binaryPath, args...)
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
			result.AddError(fmt.Sprintf("commix exited with code %d: %s",
				exitErr.ExitCode(), stderr.String()))
		}
	}

	parsed := c.ParseOutput(result.RawOutput, req.Target)
	result.AddFindings(parsed.Findings)
	return result, nil
}

// ParseOutput parses Commix output for command injection findings.
func (c *Commix) ParseOutput(output, target string) *tools.ToolResult {
	result := tools.NewToolResult(c.Name())

	injectable := strings.Contains(output, "is injectable") ||
		strings.Contains(output, "command injection") ||
		strings.Contains(output, "The parameter")

	if !injectable {
		return result
	}

	paramRe := regexp.MustCompile(`The (\w+) parameter '([^']+)' (?:seems|is|appears)`)
	techniqueRe := regexp.MustCompile(`via (.+?) technique`)

	param := ""
	technique := ""

	if m := paramRe.FindStringSubmatch(output); len(m) > 2 {
		param = m[2]
	}
	if m := techniqueRe.FindStringSubmatch(output); len(m) > 1 {
		technique = m[1]
	}

	f := core.NewFinding("Command Injection", core.SeverityCritical)
	f.URL = target
	f.Parameter = param
	f.Tool = c.Name()
	if technique != "" {
		f.Description = fmt.Sprintf("Command injection via %s technique in parameter '%s'", technique, param)
	} else {
		f.Description = fmt.Sprintf("Command injection in parameter '%s'", param)
	}
	f.WithOWASPMapping(
		[]string{"WSTG-INPV-12"},
		[]string{"A05:2025"},
		[]string{"CWE-78"},
	)
	result.AddFinding(f)

	return result
}

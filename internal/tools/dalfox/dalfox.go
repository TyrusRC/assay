package dalfox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/tools"
)

// Options configures Dalfox execution parameters.
type Options struct {
	Timeout     int  // Request timeout in seconds
	Delay       int  // Delay between requests in ms
	Workers     int  // Concurrent workers
	OnlyPoC     bool // Only report PoC-verified XSS
	WAF         bool // Enable WAF evasion
	BlindURL    string
	CustomAlert string // Custom alert value for verification
}

func defaultOptions() Options {
	return Options{
		Timeout: 10,
		Workers: 1,
	}
}

// Dalfox wraps the Dalfox XSS scanning tool.
type Dalfox struct {
	binaryPath string
	version    string
	options    Options
}

// New creates a new Dalfox instance.
func New() *Dalfox {
	d := &Dalfox{options: defaultOptions()}
	d.findBinary()
	return d
}

func (d *Dalfox) findBinary() {
	if path, err := exec.LookPath("dalfox"); err == nil {
		d.binaryPath = path
		return
	}
	for _, path := range []string{
		"/usr/bin/dalfox",
		"/usr/local/bin/dalfox",
		"/home/kali/go/bin/dalfox",
		"/root/go/bin/dalfox",
	} {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			d.binaryPath = path
			return
		}
	}
}

func (d *Dalfox) Name() string    { return "dalfox" }
func (d *Dalfox) IsAvailable() bool { return d.binaryPath != "" }

func (d *Dalfox) Version() string {
	if d.version != "" {
		return d.version
	}
	if !d.IsAvailable() {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, d.binaryPath, "version").Output()
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`v?([0-9]+\.[0-9]+\.[0-9]+)`)
	if m := re.FindStringSubmatch(string(out)); len(m) > 1 {
		d.version = m[1]
	}
	return d.version
}

func (d *Dalfox) HealthCheck() error {
	if !d.IsAvailable() {
		return fmt.Errorf("dalfox binary not found")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, d.binaryPath, "version").Run()
}

// WithOptions sets custom options.
func (d *Dalfox) WithOptions(opts Options) *Dalfox {
	d.options = opts
	return d
}

// BuildArgs builds command line arguments for Dalfox.
func (d *Dalfox) BuildArgs(req *tools.ToolRequest) []string {
	args := []string{
		"url", req.Target,
		"--silence",
		"--format", "json",
	}

	if req.Method != "" && req.Method != "GET" {
		args = append(args, "--method", req.Method)
	}
	if req.Data != "" {
		args = append(args, "--data", req.Data)
	}
	for name, value := range req.Headers {
		args = append(args, "--header", fmt.Sprintf("%s: %s", name, value))
	}
	if req.Cookies != "" {
		args = append(args, "--cookie", req.Cookies)
	}
	if req.Proxy != "" {
		args = append(args, "--proxy", req.Proxy)
	}
	if d.options.Timeout > 0 {
		args = append(args, "--timeout", fmt.Sprintf("%d", d.options.Timeout))
	}
	if d.options.Workers > 0 {
		args = append(args, "-w", fmt.Sprintf("%d", d.options.Workers))
	}
	if d.options.WAF {
		args = append(args, "--waf-evasion")
	}
	if d.options.BlindURL != "" {
		args = append(args, "--blind", d.options.BlindURL)
	}
	if d.options.OnlyPoC {
		args = append(args, "--only-poc", "r,v")
	}

	if req.OutputDir != "" {
		args = append(args, "--output", req.OutputDir+"/dalfox.json")
	}

	args = append(args, req.CustomArgs...)
	return args
}

// dalfoxResult represents a single Dalfox JSON output line.
type dalfoxResult struct {
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	Param      string `json:"param"`
	PoC        string `json:"poc"`
	InjectType string `json:"inject_type"`
	CWE        string `json:"cwe"`
	Message    string `json:"message_str"`
}

// Execute runs Dalfox against the target.
func (d *Dalfox) Execute(ctx context.Context, req *tools.ToolRequest) (*tools.ToolResult, error) {
	start := time.Now()
	result := tools.NewToolResult(d.Name())

	if !d.IsAvailable() {
		result.AddError("dalfox binary not found")
		return result, fmt.Errorf("dalfox not available")
	}

	args := d.BuildArgs(req)
	cmd := exec.CommandContext(ctx, d.binaryPath, args...)

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
			result.AddError(fmt.Sprintf("dalfox exited with code %d: %s",
				exitErr.ExitCode(), stderr.String()))
		}
	}

	parsed := d.ParseOutput(result.RawOutput, req.Target)
	result.AddFindings(parsed.Findings)
	return result, nil
}

// ParseOutput parses Dalfox JSON output and extracts findings.
func (d *Dalfox) ParseOutput(output, target string) *tools.ToolResult {
	result := tools.NewToolResult(d.Name())

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var dr dalfoxResult
		if err := json.Unmarshal([]byte(line), &dr); err != nil {
			continue
		}
		if dr.Type == "" && dr.PoC == "" {
			continue
		}

		sev := d.mapSeverity(dr)
		finding := core.NewFinding("Cross-Site Scripting (XSS)", sev)
		finding.URL = target
		finding.Parameter = dr.Param
		finding.Evidence = dr.PoC
		finding.Tool = d.Name()

		desc := "XSS"
		switch strings.ToLower(dr.InjectType) {
		case "r", "reflected":
			desc = "Reflected XSS"
		case "v", "verified":
			desc = "Verified XSS (PoC confirmed)"
		case "g", "grep":
			desc = "Potential XSS (grep match)"
		}
		finding.Description = fmt.Sprintf("%s in parameter '%s'", desc, dr.Param)
		finding.WithOWASPMapping(
			[]string{"WSTG-INPV-01", "WSTG-INPV-02"},
			[]string{"A05:2025"},
			[]string{"CWE-79"},
		)
		result.AddFinding(finding)
	}
	return result
}

func (d *Dalfox) mapSeverity(dr dalfoxResult) core.Severity {
	switch strings.ToLower(dr.InjectType) {
	case "v", "verified":
		return core.SeverityHigh
	case "r", "reflected":
		return core.SeverityMedium
	default:
		return core.SeverityMedium
	}
}

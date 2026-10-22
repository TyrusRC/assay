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

func (d *Dalfox) Name() string      { return "dalfox" }
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
// Real dalfox flags (v2.13+): -X (method), -d (data), -C (cookie),
// -H (header), -p (param), -w (workers), --proxy, --blind, --format.
func (d *Dalfox) BuildArgs(req *tools.ToolRequest) []string {
	args := []string{
		"url", req.Target,
		"--silence",
		"--format", "json",
		"--skip-headless",
	}

	// In autonomous mode, enable param mining (default on, but explicit).
	// In focused mode, --skip-discovery is passed via CustomArgs.
	if tools.IsAutonomous(req) {
		args = append(args, "--mining-dict", "--mining-dom")
	}

	if req.Method != "" && req.Method != "GET" {
		args = append(args, "-X", req.Method)
	}
	if req.Data != "" {
		args = append(args, "-d", req.Data)
	}
	for name, value := range req.Headers {
		args = append(args, "-H", fmt.Sprintf("%s: %s", name, value))
	}
	if req.Cookies != "" {
		args = append(args, "-C", req.Cookies)
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

	for _, a := range tools.StripInternalFlags(req.CustomArgs) {
		args = append(args, a)
	}
	return args
}

// dalfoxResult represents one finding in dalfox's JSON output.
// Real format: {"type":"V","inject_type":"inHTML-URL","poc_type":"plain",
// "method":"GET","data":"http://...?q=<payload>","param":"q",
// "payload":"<payload>","evidence":"<payload>","cwe":"CWE-79",
// "severity":"High","message_str":"..."}
type dalfoxResult struct {
	Type       string `json:"type"`
	InjectType string `json:"inject_type"`
	PoCType    string `json:"poc_type"`
	Method     string `json:"method"`
	Data       string `json:"data"`
	Param      string `json:"param"`
	Payload    string `json:"payload"`
	Evidence   string `json:"evidence"`
	CWE        string `json:"cwe"`
	Severity   string `json:"severity"`
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

// ParseOutput parses Dalfox JSON output. Dalfox --format json emits a
// JSON ARRAY (not JSONL): [{...}, {...}]. This parser handles both the
// array format and JSONL for forward compatibility.
func (d *Dalfox) ParseOutput(output, target string) *tools.ToolResult {
	result := tools.NewToolResult(d.Name())
	output = strings.TrimSpace(output)
	if output == "" {
		return result
	}

	// Try JSON array first (dalfox --format json).
	if strings.HasPrefix(output, "[") {
		var items []dalfoxResult
		if err := json.Unmarshal([]byte(output), &items); err == nil {
			for _, dr := range items {
				if f := d.resultToFinding(dr, target); f != nil {
					result.AddFinding(f)
				}
			}
			return result
		}
	}

	// Fallback: JSONL (--format jsonl or future versions).
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			continue
		}
		var dr dalfoxResult
		if err := json.Unmarshal([]byte(line), &dr); err != nil {
			continue
		}
		if f := d.resultToFinding(dr, target); f != nil {
			result.AddFinding(f)
		}
	}
	return result
}

func (d *Dalfox) resultToFinding(dr dalfoxResult, target string) *core.Finding {
	// Skip empty entries (dalfox emits {} in the array when nothing found).
	if dr.Type == "" && dr.Payload == "" && dr.Param == "" {
		return nil
	}

	sev := d.mapSeverity(dr)
	finding := core.NewFinding("Cross-Site Scripting (XSS)", sev)

	if dr.Data != "" {
		finding.URL = dr.Data
	} else {
		finding.URL = target
	}

	finding.Parameter = dr.Param
	finding.Tool = d.Name()

	if dr.Evidence != "" {
		finding.Evidence = dr.Evidence
	} else if dr.Payload != "" {
		finding.Evidence = dr.Payload
	}

	desc := "XSS"
	switch strings.ToUpper(dr.Type) {
	case "V":
		desc = "Verified XSS"
	case "R":
		desc = "Reflected XSS"
	case "G":
		desc = "Potential XSS (grep match)"
	}
	if dr.InjectType != "" {
		desc += " (" + dr.InjectType + ")"
	}
	if dr.Param != "" {
		desc += " in parameter '" + dr.Param + "'"
	}
	finding.Description = desc

	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-01", "WSTG-INPV-02"},
		[]string{"A05:2025"},
		[]string{"CWE-79"},
	)
	return finding
}

func (d *Dalfox) mapSeverity(dr dalfoxResult) core.Severity {
	// Use dalfox's own severity if present.
	switch strings.ToLower(dr.Severity) {
	case "critical":
		return core.SeverityCritical
	case "high":
		return core.SeverityHigh
	case "medium":
		return core.SeverityMedium
	case "low":
		return core.SeverityLow
	}
	// Fall back to type-based mapping.
	switch strings.ToUpper(dr.Type) {
	case "V":
		return core.SeverityHigh
	case "R":
		return core.SeverityMedium
	default:
		return core.SeverityMedium
	}
}

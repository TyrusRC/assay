package nikto

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

// Options configures Nikto execution parameters.
type Options struct {
	MaxTime int // Max execution time in seconds
	Tuning  string
	Plugins string
}

func defaultOptions() Options {
	return Options{MaxTime: 300}
}

// Nikto wraps the Nikto web server scanner.
type Nikto struct {
	binaryPath string
	version    string
	options    Options
}

// New creates a new Nikto instance.
func New() *Nikto {
	n := &Nikto{options: defaultOptions()}
	n.findBinary()
	return n
}

func (n *Nikto) findBinary() {
	if path, err := exec.LookPath("nikto"); err == nil {
		n.binaryPath = path
		return
	}
	for _, path := range []string{
		"/usr/bin/nikto",
		"/usr/local/bin/nikto",
		"/opt/nikto/nikto.pl",
	} {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			n.binaryPath = path
			return
		}
	}
}

func (n *Nikto) Name() string      { return "nikto" }
func (n *Nikto) IsAvailable() bool { return n.binaryPath != "" }

func (n *Nikto) Version() string {
	if n.version != "" {
		return n.version
	}
	if !n.IsAvailable() {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, n.binaryPath, "-Version").CombinedOutput()
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`([0-9]+\.[0-9]+\.?[0-9]*)`)
	if m := re.FindStringSubmatch(string(out)); len(m) > 1 {
		n.version = m[1]
	}
	return n.version
}

func (n *Nikto) HealthCheck() error {
	if !n.IsAvailable() {
		return fmt.Errorf("nikto binary not found")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, n.binaryPath, "-Version").Run()
}

// WithOptions sets custom options.
func (n *Nikto) WithOptions(opts Options) *Nikto {
	n.options = opts
	return n
}

// BuildArgs builds command line arguments.
func (n *Nikto) BuildArgs(req *tools.ToolRequest) []string {
	args := []string{
		"-h", req.Target,
		"-Format", "json",
		"-nointeractive",
	}

	if req.OutputDir != "" {
		args = append(args, "-output", req.OutputDir+"/nikto.json")
	}
	if req.Proxy != "" {
		args = append(args, "-useproxy", req.Proxy)
	}
	if n.options.MaxTime > 0 {
		args = append(args, "-maxtime", fmt.Sprintf("%d", n.options.MaxTime))
	}
	if n.options.Tuning != "" {
		args = append(args, "-Tuning", n.options.Tuning)
	}
	if n.options.Plugins != "" {
		args = append(args, "-Plugins", n.options.Plugins)
	}

	args = append(args, tools.StripInternalFlags(req.CustomArgs)...)
	return args
}

// niktoItem represents a single Nikto JSON finding.
type niktoItem struct {
	ID          string `json:"id"`
	OSVDBID     string `json:"OSVDB"`
	Method      string `json:"method"`
	Description string `json:"msg"`
	URL         string `json:"url"`
	References  string `json:"references"`
}

// niktoOutput represents one host entry in the Nikto JSON output.
// Nikto emits a JSON array: [{host, ip, port, vulnerabilities}, ...].
type niktoOutput struct {
	Host         string      `json:"host"`
	IP           string      `json:"ip"`
	Port         json.Number `json:"port"`
	Banner       string      `json:"server_banner"`
	Vulnerbility []niktoItem `json:"vulnerabilities"`
}

// Execute runs Nikto against the target.
func (n *Nikto) Execute(ctx context.Context, req *tools.ToolRequest) (*tools.ToolResult, error) {
	start := time.Now()
	result := tools.NewToolResult(n.Name())

	if !n.IsAvailable() {
		result.AddError("nikto binary not found")
		return result, fmt.Errorf("nikto not available")
	}

	args := n.BuildArgs(req)
	cmd := exec.CommandContext(ctx, n.binaryPath, args...)

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

	// Try JSON output first (from file if written), then parse stdout
	parsed := n.ParseOutput(result.RawOutput, req.Target)
	result.AddFindings(parsed.Findings)

	// Try reading JSON output file
	if req.OutputDir != "" {
		jsonFile := req.OutputDir + "/nikto.json"
		if data, err := os.ReadFile(jsonFile); err == nil {
			jsonParsed := n.ParseJSONOutput(data, req.Target)
			result.AddFindings(jsonParsed.Findings)
		}
	}

	return result, nil
}

// ParseOutput parses raw Nikto stdout for findings.
func (n *Nikto) ParseOutput(output, target string) *tools.ToolResult {
	result := tools.NewToolResult(n.Name())

	findingRe := regexp.MustCompile(`\+ (OSVDB-\d+|[A-Z].*?): (.+)`)
	for _, line := range strings.Split(output, "\n") {
		m := findingRe.FindStringSubmatch(line)
		if len(m) < 3 {
			continue
		}
		osvdb := m[1]
		desc := m[2]

		sev := n.classifySeverity(desc)
		f := core.NewFinding("Web Server Misconfiguration", sev)
		f.URL = target
		f.Description = desc
		f.Evidence = osvdb
		f.Tool = n.Name()
		f.WithOWASPMapping(
			[]string{"WSTG-CONF-06"},
			[]string{"A05:2025"},
			[]string{},
		)
		result.AddFinding(f)
	}

	return result
}

// ParseJSONOutput parses Nikto JSON output. Nikto emits a JSON array
// of host objects: [{host, vulnerabilities:[...]}, ...].
func (n *Nikto) ParseJSONOutput(data []byte, target string) *tools.ToolResult {
	result := tools.NewToolResult(n.Name())

	// Try array first (actual nikto format).
	var hosts []niktoOutput
	if err := json.Unmarshal(data, &hosts); err == nil {
		for _, host := range hosts {
			for _, item := range host.Vulnerbility {
				if f := n.itemToFinding(item, target); f != nil {
					result.AddFinding(f)
				}
			}
		}
		return result
	}

	// Fallback: single object (older nikto or different build).
	var single niktoOutput
	if err := json.Unmarshal(data, &single); err == nil {
		for _, item := range single.Vulnerbility {
			if f := n.itemToFinding(item, target); f != nil {
				result.AddFinding(f)
			}
		}
	}

	return result
}

func (n *Nikto) itemToFinding(item niktoItem, target string) *core.Finding {
	// Skip FAIL connection items.
	if item.ID == "FAIL" {
		return nil
	}

	sev := n.classifySeverityByID(item.ID, item.Description)
	f := core.NewFinding("Web Server Misconfiguration", sev)
	if item.URL != "" && item.URL != "/" {
		f.URL = target + item.URL
	} else {
		f.URL = target
	}
	f.Description = item.Description
	f.Tool = n.Name()

	if item.ID != "" {
		f.Evidence = "Nikto-" + item.ID
	}
	if item.OSVDBID != "" && item.OSVDBID != "0" {
		f.Evidence = "OSVDB-" + item.OSVDBID
	}

	f.WithOWASPMapping(
		[]string{"WSTG-CONF-06"},
		[]string{"A05:2025"},
		[]string{},
	)
	return f
}

func (n *Nikto) classifySeverity(desc string) core.Severity {
	lower := strings.ToLower(desc)
	if strings.Contains(lower, "remote code execution") ||
		strings.Contains(lower, "remote command execution") ||
		strings.Contains(lower, "arbitrary file") {
		return core.SeverityCritical
	}
	if strings.Contains(lower, "sql injection") ||
		strings.Contains(lower, "file inclusion") ||
		strings.Contains(lower, "directory traversal") {
		return core.SeverityHigh
	}
	if strings.Contains(lower, "xss") ||
		strings.Contains(lower, "redirect") ||
		strings.Contains(lower, "credential") ||
		strings.Contains(lower, ".env file") {
		return core.SeverityMedium
	}
	return core.SeverityLow
}

// classifySeverityByID uses both the nikto ID prefix and the
// description text to map severity. ID ranges observed:
// 007xxx = sensitive file exposure (high), 6xxxxx = version/info (low),
// 013xxx = missing headers (info/low), 000xxx = general (medium).
func (n *Nikto) classifySeverityByID(id, desc string) core.Severity {
	// Description-based takes priority for known vuln keywords.
	descSev := n.classifySeverity(desc)
	if descSev == core.SeverityCritical || descSev == core.SeverityHigh {
		return descSev
	}

	if len(id) >= 3 {
		prefix := id[:3]
		switch {
		case prefix == "007":
			return core.SeverityHigh
		case strings.HasPrefix(id, "6"):
			return core.SeverityLow
		case prefix == "013":
			return core.SeverityLow
		}
	}

	return descSev
}

package wpscan

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

// Options configures WPScan execution parameters.
type Options struct {
	APIToken      string
	Enumerate     string // vp,vt,u,cb,dbe
	DetectionMode string // mixed, passive, aggressive
}

func defaultOptions() Options {
	return Options{
		Enumerate:     "vp,vt,u",
		DetectionMode: "mixed",
	}
}

// WPScan wraps the WPScan WordPress scanner.
type WPScan struct {
	binaryPath string
	version    string
	options    Options
}

// New creates a new WPScan instance.
func New() *WPScan {
	w := &WPScan{options: defaultOptions()}
	w.findBinary()
	return w
}

func (w *WPScan) findBinary() {
	if path, err := exec.LookPath("wpscan"); err == nil {
		w.binaryPath = path
		return
	}
	for _, path := range []string{
		"/usr/bin/wpscan",
		"/usr/local/bin/wpscan",
		"/opt/wpscan/wpscan.rb",
	} {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			w.binaryPath = path
			return
		}
	}
}

func (w *WPScan) Name() string      { return "wpscan" }
func (w *WPScan) IsAvailable() bool { return w.binaryPath != "" }

func (w *WPScan) Version() string {
	if w.version != "" {
		return w.version
	}
	if !w.IsAvailable() {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, w.binaryPath, "--version").Output()
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`([0-9]+\.[0-9]+\.?[0-9]*)`)
	if m := re.FindStringSubmatch(string(out)); len(m) > 1 {
		w.version = m[1]
	}
	return w.version
}

func (w *WPScan) HealthCheck() error {
	if !w.IsAvailable() {
		return fmt.Errorf("wpscan binary not found")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, w.binaryPath, "--version").Run()
}

// WithOptions sets custom options.
func (w *WPScan) WithOptions(opts Options) *WPScan {
	w.options = opts
	return w
}

// BuildArgs builds command line arguments.
func (w *WPScan) BuildArgs(req *tools.ToolRequest) []string {
	args := []string{
		"--url", req.Target,
		"--format", "json",
		"--no-banner",
		"--disable-tls-checks",
	}

	if w.options.Enumerate != "" {
		args = append(args, "--enumerate", w.options.Enumerate)
	}
	if w.options.DetectionMode != "" {
		args = append(args, "--detection-mode", w.options.DetectionMode)
	}
	if w.options.APIToken != "" {
		args = append(args, "--api-token", w.options.APIToken)
	}

	if req.Proxy != "" {
		args = append(args, "--proxy", req.Proxy)
	}
	if req.Cookies != "" {
		args = append(args, "--cookie-string", req.Cookies)
	}
	if req.OutputDir != "" {
		args = append(args, "--output", req.OutputDir+"/wpscan.json")
	}

	args = append(args, req.CustomArgs...)
	return args
}

// wpscanOutput represents the WPScan JSON output.
type wpscanOutput struct {
	Version      *wpscanVersion                   `json:"version"`
	MainTheme    *wpscanTheme                     `json:"main_theme"`
	Plugins      map[string]*wpscanPlugin         `json:"plugins"`
	Themes       map[string]*wpscanTheme          `json:"themes"`
	Users        map[string]*wpscanUser           `json:"users"`
	PasswordAttack interface{}                    `json:"password_attack"`
	Vuln         []wpscanVulnEntry                `json:"vulnerabilities"`
	Interesting  []wpscanInteresting              `json:"interesting_findings"`
}

type wpscanVersion struct {
	Number  string            `json:"number"`
	Status  string            `json:"status"`
	Vulns   []wpscanVulnEntry `json:"vulnerabilities"`
}

type wpscanPlugin struct {
	Slug    string            `json:"slug"`
	Version *wpscanVerInfo    `json:"version"`
	Vulns   []wpscanVulnEntry `json:"vulnerabilities"`
}

type wpscanTheme struct {
	Slug    string            `json:"slug"`
	Version *wpscanVerInfo    `json:"version"`
	Vulns   []wpscanVulnEntry `json:"vulnerabilities"`
}

type wpscanVerInfo struct {
	Number string `json:"number"`
}

type wpscanVulnEntry struct {
	Title      string            `json:"title"`
	FixedIn    string            `json:"fixed_in"`
	References map[string][]string `json:"references"`
	Type       string            `json:"type"`
}

type wpscanUser struct {
	ID   int    `json:"id"`
	Slug string `json:"slug"`
}

type wpscanInteresting struct {
	URL         string   `json:"url"`
	Type        string   `json:"type"`
	Description string   `json:"to_s"`
	References  map[string][]string `json:"references"`
	Entries     []string `json:"interesting_entries"`
}

// Execute runs WPScan against the target.
func (w *WPScan) Execute(ctx context.Context, req *tools.ToolRequest) (*tools.ToolResult, error) {
	start := time.Now()
	result := tools.NewToolResult(w.Name())

	if !w.IsAvailable() {
		result.AddError("wpscan binary not found")
		return result, fmt.Errorf("wpscan not available")
	}

	args := w.BuildArgs(req)
	cmd := exec.CommandContext(ctx, w.binaryPath, args...)

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

	parsed := w.ParseJSONOutput([]byte(result.RawOutput), req.Target)
	result.AddFindings(parsed.Findings)

	// Try reading output file
	if req.OutputDir != "" {
		if data, err := os.ReadFile(req.OutputDir + "/wpscan.json"); err == nil {
			fileParsed := w.ParseJSONOutput(data, req.Target)
			result.AddFindings(fileParsed.Findings)
		}
	}

	return result, nil
}

// ParseJSONOutput parses WPScan JSON output.
func (w *WPScan) ParseJSONOutput(data []byte, target string) *tools.ToolResult {
	result := tools.NewToolResult(w.Name())

	var output wpscanOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return result
	}

	// Core version vulnerabilities
	if output.Version != nil {
		for _, v := range output.Version.Vulns {
			f := w.vulnToFinding(v, target, "WordPress Core "+output.Version.Number)
			result.AddFinding(f)
		}
	}

	// Plugin vulnerabilities
	for slug, plugin := range output.Plugins {
		for _, v := range plugin.Vulns {
			ver := ""
			if plugin.Version != nil {
				ver = plugin.Version.Number
			}
			f := w.vulnToFinding(v, target, fmt.Sprintf("Plugin %s %s", slug, ver))
			result.AddFinding(f)
		}
	}

	// Theme vulnerabilities
	for slug, theme := range output.Themes {
		for _, v := range theme.Vulns {
			ver := ""
			if theme.Version != nil {
				ver = theme.Version.Number
			}
			f := w.vulnToFinding(v, target, fmt.Sprintf("Theme %s %s", slug, ver))
			result.AddFinding(f)
		}
	}

	return result
}

func (w *WPScan) vulnToFinding(v wpscanVulnEntry, target, component string) *core.Finding {
	sev := w.classifySeverity(v.Title, v.Type)
	f := core.NewFinding("WordPress Vulnerability", sev)
	f.URL = target
	f.Title = v.Title
	f.Description = fmt.Sprintf("%s in %s", v.Title, component)
	f.Tool = w.Name()

	if v.FixedIn != "" {
		f.Remediation = fmt.Sprintf("Update to version %s or later", v.FixedIn)
	}

	var refs []string
	for refType, refURLs := range v.References {
		for _, u := range refURLs {
			refs = append(refs, fmt.Sprintf("[%s] %s", refType, u))
		}
	}
	f.References = refs

	f.WithOWASPMapping(
		[]string{"WSTG-CONF-08"},
		[]string{"A06:2025"},
		[]string{},
	)
	return f
}

func (w *WPScan) classifySeverity(title, vulnType string) core.Severity {
	lower := strings.ToLower(title)
	if strings.Contains(lower, "rce") ||
		strings.Contains(lower, "remote code") ||
		strings.Contains(lower, "sql injection") ||
		strings.Contains(lower, "arbitrary file") {
		return core.SeverityCritical
	}
	if strings.Contains(lower, "xss") ||
		strings.Contains(lower, "authentication bypass") ||
		strings.Contains(lower, "privilege escalation") {
		return core.SeverityHigh
	}
	if strings.Contains(lower, "csrf") ||
		strings.Contains(lower, "ssrf") ||
		strings.Contains(lower, "redirect") {
		return core.SeverityMedium
	}
	return core.SeverityMedium
}

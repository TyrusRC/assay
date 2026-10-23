package feroxbuster

import (
	"bufio"
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

// Options configures feroxbuster execution.
type Options struct {
	Threads   int
	Timeout   int    // per-request timeout in seconds
	Wordlist  string // path to wordlist (auto-detected if empty)
	Depth     int    // recursion depth
	Insecure  bool   // skip TLS verification
}

func defaultOptions() Options {
	return Options{Threads: 10, Timeout: 7, Depth: 1}
}

// Feroxbuster wraps the feroxbuster directory fuzzing tool.
type Feroxbuster struct {
	binaryPath string
	version    string
	options    Options
}

// New creates a new Feroxbuster instance.
func New() *Feroxbuster {
	f := &Feroxbuster{options: defaultOptions()}
	f.findBinary()
	return f
}

func (f *Feroxbuster) findBinary() {
	if p, err := exec.LookPath("feroxbuster"); err == nil {
		f.binaryPath = p
		return
	}
	for _, p := range []string{"/usr/bin/feroxbuster", "/usr/local/bin/feroxbuster"} {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			f.binaryPath = p
			return
		}
	}
}

func (f *Feroxbuster) Name() string      { return "feroxbuster" }
func (f *Feroxbuster) IsAvailable() bool { return f.binaryPath != "" }

func (f *Feroxbuster) Version() string {
	if f.version != "" {
		return f.version
	}
	if !f.IsAvailable() {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, f.binaryPath, "--version").CombinedOutput()
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`([0-9]+\.[0-9]+\.[0-9]+)`)
	if m := re.FindStringSubmatch(string(out)); len(m) > 1 {
		f.version = m[1]
	}
	return f.version
}

func (f *Feroxbuster) HealthCheck() error {
	if !f.IsAvailable() {
		return fmt.Errorf("feroxbuster not found")
	}
	return nil
}

// WithOptions sets custom options.
func (f *Feroxbuster) WithOptions(opts Options) *Feroxbuster {
	f.options = opts
	return f
}

func (f *Feroxbuster) resolveWordlist() string {
	if f.options.Wordlist != "" {
		return f.options.Wordlist
	}
	candidates := []string{
		"/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
		"/usr/share/wordlists/dirb/common.txt",
		"/usr/share/seclists/Discovery/Web-Content/common.txt",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// Execute runs feroxbuster and returns discovered URLs as findings.
func (f *Feroxbuster) Execute(ctx context.Context, req *tools.ToolRequest) (*tools.ToolResult, error) {
	start := time.Now()
	result := tools.NewToolResult(f.Name())
	result.IsDiscovery = true

	if !f.IsAvailable() {
		result.AddError("feroxbuster not found")
		return result, fmt.Errorf("feroxbuster not available")
	}

	args := []string{
		"-u", req.Target,
		"--json",
		"-q",
		"--no-state",
		"-t", fmt.Sprintf("%d", f.options.Threads),
		"--timeout", fmt.Sprintf("%d", f.options.Timeout),
		"-d", fmt.Sprintf("%d", f.options.Depth),
	}

	wl := f.resolveWordlist()
	if wl != "" {
		args = append(args, "-w", wl)
	}

	if req.Proxy != "" {
		args = append(args, "--proxy", req.Proxy)
	}
	if f.options.Insecure || req.Proxy != "" {
		args = append(args, "-k")
	}
	for k, v := range req.Headers {
		args = append(args, "-H", fmt.Sprintf("%s: %s", k, v))
	}
	if req.Cookies != "" {
		args = append(args, "-b", req.Cookies)
	}

	args = append(args, tools.StripInternalFlags(req.CustomArgs)...)

	cmd := exec.CommandContext(ctx, f.binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	_ = cmd.Run()
	result.ExecutionTime = time.Since(start)
	result.RawOutput = stdout.String()

	scanner := bufio.NewScanner(strings.NewReader(result.RawOutput))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var entry struct {
			Type             string `json:"type"`
			URL              string `json:"url"`
			Status           int    `json:"status"`
			ContentLength    int    `json:"content_length"`
			Lines            int    `json:"lines"`
			Words            int    `json:"words"`
			RedirectLocation string `json:"redirect_location"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if entry.URL == "" || entry.Type == "statistics" {
			continue
		}
		if entry.Status != 200 && entry.Status != 301 && entry.Status != 302 && entry.Status != 403 {
			continue
		}
		finding := core.NewFinding("Discovered Path", core.SeverityInfo)
		finding.URL = entry.URL
		finding.Tool = f.Name()
		finding.Description = fmt.Sprintf("Directory fuzzing found %s (status %d, %d bytes)",
			entry.URL, entry.Status, entry.ContentLength)
		result.AddFinding(finding)
		result.DiscoveredURLs = append(result.DiscoveredURLs, entry.URL)
	}

	return result, nil
}

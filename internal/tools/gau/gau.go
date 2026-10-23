package gau

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/tools"
)

// Options configures gau execution.
type Options struct {
	Threads   int
	Timeout   int    // seconds
	Providers string // comma-separated: wayback,commoncrawl,otx,urlscan
}

func defaultOptions() Options {
	return Options{Threads: 5, Timeout: 30, Providers: "wayback,commoncrawl,otx,urlscan"}
}

// Gau wraps the gau historical URL discovery tool.
type Gau struct {
	binaryPath string
	version    string
	options    Options
}

// New creates a new Gau instance.
func New() *Gau {
	g := &Gau{options: defaultOptions()}
	g.findBinary()
	return g
}

func (g *Gau) findBinary() {
	if p, err := exec.LookPath("gau"); err == nil {
		g.binaryPath = p
		return
	}
	for _, p := range []string{
		"/usr/bin/gau", "/usr/local/bin/gau",
		"/home/kali/go/bin/gau", "/root/go/bin/gau",
	} {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			g.binaryPath = p
			return
		}
	}
}

func (g *Gau) Name() string      { return "gau" }
func (g *Gau) IsAvailable() bool { return g.binaryPath != "" }

func (g *Gau) Version() string {
	if g.version != "" {
		return g.version
	}
	if !g.IsAvailable() {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, g.binaryPath, "--version").CombinedOutput()
	if err == nil {
		re := regexp.MustCompile(`v?([0-9]+\.[0-9]+\.?[0-9]*)`)
		if m := re.FindStringSubmatch(string(out)); len(m) > 1 {
			g.version = m[1]
		}
	}
	return g.version
}

func (g *Gau) HealthCheck() error {
	if !g.IsAvailable() {
		return fmt.Errorf("gau not found")
	}
	return nil
}

// WithOptions sets custom options.
func (g *Gau) WithOptions(opts Options) *Gau {
	g.options = opts
	return g
}

// Execute runs gau against the target's domain and returns discovered URLs.
func (g *Gau) Execute(ctx context.Context, req *tools.ToolRequest) (*tools.ToolResult, error) {
	start := time.Now()
	result := tools.NewToolResult(g.Name())
	result.IsDiscovery = true

	if !g.IsAvailable() {
		result.AddError("gau not found")
		return result, fmt.Errorf("gau not available")
	}

	// Extract domain from target URL.
	parsed, err := url.Parse(req.Target)
	if err != nil || parsed.Host == "" {
		result.AddError("invalid target URL")
		return result, fmt.Errorf("cannot extract domain from %s", req.Target)
	}
	domain := parsed.Hostname()

	args := []string{
		"--json",
		"--threads", fmt.Sprintf("%d", g.options.Threads),
		"--providers", g.options.Providers,
		domain,
	}

	args = append(args, tools.StripInternalFlags(req.CustomArgs)...)

	cmd := exec.CommandContext(ctx, g.binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	_ = cmd.Run()
	result.ExecutionTime = time.Since(start)
	result.RawOutput = stdout.String()

	seen := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(result.RawOutput))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var entry struct {
			URL string `json:"url"`
		}
		if strings.HasPrefix(line, "{") {
			if json.Unmarshal([]byte(line), &entry) != nil || entry.URL == "" {
				continue
			}
		} else {
			// plain text mode: one URL per line
			entry.URL = line
		}

		if seen[entry.URL] {
			continue
		}
		seen[entry.URL] = true

		// Only include URLs that belong to the target domain.
		u, perr := url.Parse(entry.URL)
		if perr != nil || u.Hostname() != domain {
			continue
		}

		finding := core.NewFinding("Historical URL", core.SeverityInfo)
		finding.URL = entry.URL
		finding.Tool = g.Name()
		finding.Description = fmt.Sprintf("Historical URL from archive: %s", entry.URL)
		result.AddFinding(finding)
		result.DiscoveredURLs = append(result.DiscoveredURLs, entry.URL)
	}

	return result, nil
}

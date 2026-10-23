package katana

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

// Options configures katana execution.
type Options struct {
	Depth       int
	Concurrency int
	Timeout     int  // seconds
	Headless    bool // enable headless Chrome crawling
	KnownFiles  bool // parse robots.txt, sitemap.xml
	FormFill    bool // fill and submit forms
}

func defaultOptions() Options {
	return Options{Depth: 2, Concurrency: 10, Timeout: 30, KnownFiles: true}
}

// Katana wraps the katana web crawler.
type Katana struct {
	binaryPath string
	version    string
	options    Options
}

// New creates a new Katana instance.
func New() *Katana {
	k := &Katana{options: defaultOptions()}
	k.findBinary()
	return k
}

func (k *Katana) findBinary() {
	if p, err := exec.LookPath("katana"); err == nil {
		k.binaryPath = p
		return
	}
	for _, p := range []string{
		"/usr/bin/katana", "/usr/local/bin/katana",
		"/home/kali/go/bin/katana", "/root/go/bin/katana",
	} {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			k.binaryPath = p
			return
		}
	}
}

func (k *Katana) Name() string      { return "katana" }
func (k *Katana) IsAvailable() bool { return k.binaryPath != "" }

func (k *Katana) Version() string {
	if k.version != "" {
		return k.version
	}
	if !k.IsAvailable() {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, k.binaryPath, "-version").CombinedOutput()
	if err == nil {
		re := regexp.MustCompile(`v?([0-9]+\.[0-9]+\.?[0-9]*)`)
		if m := re.FindStringSubmatch(string(out)); len(m) > 1 {
			k.version = m[1]
		}
	}
	return k.version
}

func (k *Katana) HealthCheck() error {
	if !k.IsAvailable() {
		return fmt.Errorf("katana not found")
	}
	return nil
}

// WithOptions sets custom options.
func (k *Katana) WithOptions(opts Options) *Katana {
	k.options = opts
	return k
}

// Execute runs katana and returns discovered URLs.
func (k *Katana) Execute(ctx context.Context, req *tools.ToolRequest) (*tools.ToolResult, error) {
	start := time.Now()
	result := tools.NewToolResult(k.Name())
	result.IsDiscovery = true

	if !k.IsAvailable() {
		result.AddError("katana not found")
		return result, fmt.Errorf("katana not available")
	}

	args := []string{
		"-u", req.Target,
		"-jsonl",
		"-silent",
		"-no-color",
		"-d", fmt.Sprintf("%d", k.options.Depth),
		"-c", fmt.Sprintf("%d", k.options.Concurrency),
		"-timeout", fmt.Sprintf("%d", k.options.Timeout),
	}

	if k.options.Headless {
		args = append(args, "-headless")
	}
	if k.options.KnownFiles {
		args = append(args, "-known-files", "all")
	}
	if k.options.FormFill {
		args = append(args, "-automatic-form-fill")
	}

	if req.Proxy != "" {
		args = append(args, "-proxy", req.Proxy)
	}
	for hk, hv := range req.Headers {
		args = append(args, "-H", fmt.Sprintf("%s: %s", hk, hv))
	}

	args = append(args, tools.StripInternalFlags(req.CustomArgs)...)

	cmd := exec.CommandContext(ctx, k.binaryPath, args...)
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
			URL       string `json:"request>url"`
			Endpoint  string `json:"request>endpoint"`
			Method    string `json:"request>method"`
			Body      string `json:"request>body"`
			Source    string `json:"request>source"`
			Tag       string `json:"request>tag"`
			Attribute string `json:"request>attribute"`
		}
		// katana JSONL: {"request":{"method":"GET","endpoint":"...","url":"...",...}}
		var raw map[string]json.RawMessage
		if json.Unmarshal([]byte(line), &raw) != nil {
			continue
		}
		reqData, ok := raw["request"]
		if !ok {
			// flat format: {"url": "..."}
			var flat struct{ URL string `json:"url"` }
			if json.Unmarshal([]byte(line), &flat) == nil && flat.URL != "" {
				entry.URL = flat.URL
			} else {
				continue
			}
		} else {
			var reqObj struct {
				URL    string `json:"url"`
				Method string `json:"method"`
				Body   string `json:"body"`
			}
			if json.Unmarshal(reqData, &reqObj) == nil {
				entry.URL = reqObj.URL
				entry.Method = reqObj.Method
				entry.Body = reqObj.Body
			}
		}

		if entry.URL == "" || seen[entry.URL] {
			continue
		}
		seen[entry.URL] = true

		finding := core.NewFinding("Crawled URL", core.SeverityInfo)
		finding.URL = entry.URL
		finding.Tool = k.Name()
		finding.Description = fmt.Sprintf("Crawled: %s %s", entry.Method, entry.URL)
		result.AddFinding(finding)
		result.DiscoveredURLs = append(result.DiscoveredURLs, entry.URL)
	}

	return result, nil
}

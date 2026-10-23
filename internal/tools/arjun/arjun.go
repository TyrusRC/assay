package arjun

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/tools"
)

// Options configures arjun execution.
type Options struct {
	Threads int
	Methods string // comma-separated: GET,POST,JSON
	Stable  bool   // throttle requests for stability
}

func defaultOptions() Options {
	return Options{Threads: 5, Methods: "GET,POST,JSON"}
}

// Arjun wraps the arjun hidden parameter discovery tool.
type Arjun struct {
	binaryPath string
	version    string
	options    Options
}

// New creates a new Arjun instance.
func New() *Arjun {
	a := &Arjun{options: defaultOptions()}
	a.findBinary()
	return a
}

func (a *Arjun) findBinary() {
	if p, err := exec.LookPath("arjun"); err == nil {
		a.binaryPath = p
		return
	}
	for _, p := range []string{
		"/usr/bin/arjun", "/usr/local/bin/arjun",
		"/home/kali/.local/bin/arjun",
	} {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			a.binaryPath = p
			return
		}
	}
}

func (a *Arjun) Name() string      { return "arjun" }
func (a *Arjun) IsAvailable() bool { return a.binaryPath != "" }

func (a *Arjun) Version() string {
	if a.version != "" {
		return a.version
	}
	if !a.IsAvailable() {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, a.binaryPath, "--help").CombinedOutput()
	if err == nil {
		re := regexp.MustCompile(`v?([0-9]+\.[0-9]+\.?[0-9]*)`)
		if m := re.FindStringSubmatch(string(out)); len(m) > 1 {
			a.version = m[1]
		}
	}
	return a.version
}

func (a *Arjun) HealthCheck() error {
	if !a.IsAvailable() {
		return fmt.Errorf("arjun not found")
	}
	return nil
}

// WithOptions sets custom options.
func (a *Arjun) WithOptions(opts Options) *Arjun {
	a.options = opts
	return a
}

// Execute runs arjun and returns discovered parameters.
func (a *Arjun) Execute(ctx context.Context, req *tools.ToolRequest) (*tools.ToolResult, error) {
	start := time.Now()
	result := tools.NewToolResult(a.Name())
	result.IsDiscovery = true

	if !a.IsAvailable() {
		result.AddError("arjun not found")
		return result, fmt.Errorf("arjun not available")
	}

	outFile := ""
	if req.OutputDir != "" {
		outFile = req.OutputDir + "/arjun.json"
	} else {
		tmp, err := os.CreateTemp("", "arjun-*.json")
		if err != nil {
			result.AddError(fmt.Sprintf("cannot create temp file: %v", err))
			return result, err
		}
		outFile = tmp.Name()
		tmp.Close()
		defer os.Remove(outFile)
	}

	target := tools.NormalizeURLForIPv4(req.Target)

	args := []string{
		"-u", target,
		"-oJ", outFile,
		"-t", fmt.Sprintf("%d", a.options.Threads),
		"-m", a.options.Methods,
	}

	if a.options.Stable {
		args = append(args, "--stable")
	}
	for k, v := range req.Headers {
		args = append(args, "--headers", fmt.Sprintf("%s: %s", k, v))
	}

	args = append(args, tools.StripInternalFlags(req.CustomArgs)...)

	cmd := exec.CommandContext(ctx, a.binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	_ = cmd.Run()
	result.ExecutionTime = time.Since(start)
	result.RawOutput = stdout.String()

	data, err := os.ReadFile(outFile)
	if err != nil {
		return result, nil
	}

	// arjun JSON output: {"<url>": {"method": "...", "params": ["p1","p2",...]}, ...}
	// or: [{"url": "...", "params": [...]}]
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(data, &parsed); err == nil {
		for url, raw := range parsed {
			var entry struct {
				Params []string `json:"params"`
				Method string   `json:"method"`
			}
			if json.Unmarshal(raw, &entry) == nil && len(entry.Params) > 0 {
				for _, p := range entry.Params {
					finding := core.NewFinding("Hidden Parameter Discovered", core.SeverityInfo)
					finding.URL = url
					finding.Parameter = p
					finding.Tool = a.Name()
					finding.Description = fmt.Sprintf("Hidden parameter '%s' discovered via %s on %s", p, entry.Method, url)
					result.AddFinding(finding)
					result.DiscoveredParams = append(result.DiscoveredParams, tools.DiscoveredParam{
						URL:       url,
						Name:      p,
						Method:    entry.Method,
						Location:  "query",
					})
				}
			}
		}
	}

	return result, nil
}

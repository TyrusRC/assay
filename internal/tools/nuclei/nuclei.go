package nuclei

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

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/tools"
)

// Options configures Nuclei execution parameters. Only fields that the
// scanner has reason to set per-run are exposed here; the rest fall
// through via tools.ToolRequest.CustomArgs.
type Options struct {
	// TemplatePaths is one or more `-t` paths (templates dir or single file).
	// Empty means use Nuclei's default template store (~/nuclei-templates).
	TemplatePaths []string

	// Tags filters templates by tag. Empty means no tag filter.
	Tags []string

	// Severity filters findings by severity. Empty means all severities.
	// Valid values: "info", "low", "medium", "high", "critical".
	Severity []string

	// Concurrency is the number of templates run concurrently (-c).
	// 0 falls back to Nuclei's default.
	Concurrency int

	// RateLimit is the maximum requests per second (-rl). 0 = no cap.
	RateLimit int

	// Timeout is the per-request timeout in seconds (-timeout). 0 = default.
	Timeout int

	// Retries is the number of retries per template (-retries). 0 = default.
	Retries int

	// Silent suppresses banner / progress output (-silent).
	Silent bool
}

// defaultOptions returns sensible defaults for in-scanner use: silent
// output and JSONL parsing — no template filter, let the user's local
// template store decide coverage.
func defaultOptions() Options {
	return Options{
		Silent:      true,
		Concurrency: 25,
		Timeout:     10,
		Retries:     1,
	}
}

// Nuclei wraps the upstream `nuclei` binary.
type Nuclei struct {
	binaryPath string
	version    string
	options    Options
}

// New creates a Nuclei wrapper, locating the binary on $PATH or in
// common installation paths. The wrapper is safe to construct even when
// the binary is absent — IsAvailable() reports false and Execute()
// returns an error rather than panicking.
func New() *Nuclei {
	n := &Nuclei{options: defaultOptions()}
	n.findBinary()
	return n
}

// findBinary locates the nuclei binary on $PATH or in common locations.
func (n *Nuclei) findBinary() {
	if path, err := exec.LookPath("nuclei"); err == nil {
		n.binaryPath = path
		return
	}
	candidates := []string{
		"/usr/bin/nuclei",
		"/usr/local/bin/nuclei",
		"/opt/nuclei/nuclei",
	}
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			n.binaryPath = p
			return
		}
	}
}

// Name returns the tool name.
func (n *Nuclei) Name() string { return "nuclei" }

// IsAvailable reports whether the binary was located.
func (n *Nuclei) IsAvailable() bool { return n.binaryPath != "" }

// Version reads the nuclei version string. Cached after first call.
func (n *Nuclei) Version() string {
	if n.version != "" {
		return n.version
	}
	if !n.IsAvailable() {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, n.binaryPath, "-version")
	// Some nuclei builds print version to stderr, others stdout.
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`(?i)nuclei\s+(?:engine\s+)?version[:\s]*v?([0-9][0-9A-Za-z._\-+]*)`)
	if m := re.FindStringSubmatch(string(out)); len(m) > 1 {
		n.version = m[1]
	}
	return n.version
}

// HealthCheck verifies the binary runs and prints a parseable version.
func (n *Nuclei) HealthCheck() error {
	if !n.IsAvailable() {
		return fmt.Errorf("nuclei binary not found")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, n.binaryPath, "-version").Run(); err != nil {
		return fmt.Errorf("nuclei health check failed: %w", err)
	}
	return nil
}

// WithOptions overrides the default options.
func (n *Nuclei) WithOptions(opts Options) *Nuclei {
	n.options = opts
	return n
}

// Options returns the current options.
func (n *Nuclei) Options() Options { return n.options }

// DefaultOptions returns the package defaults — used by callers that
// want to start from the recommended baseline and tweak a few fields.
func (n *Nuclei) DefaultOptions() Options { return defaultOptions() }

// BuildArgs renders the Nuclei command-line arguments for a request.
// Public so tests can assert the arg shape without invoking the binary.
func (n *Nuclei) BuildArgs(req *tools.ToolRequest) []string {
	args := []string{
		"-target", req.Target,
		"-jsonl",       // line-delimited JSON on stdout
		"-no-color",    // strip ANSI from any non-JSONL output we capture
		"-disable-update-check",
	}
	if n.options.Silent {
		args = append(args, "-silent")
	}
	for _, p := range n.options.TemplatePaths {
		args = append(args, "-t", p)
	}
	if len(n.options.Tags) > 0 {
		args = append(args, "-tags", strings.Join(n.options.Tags, ","))
	}
	if len(n.options.Severity) > 0 {
		args = append(args, "-severity", strings.Join(n.options.Severity, ","))
	}
	if n.options.Concurrency > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", n.options.Concurrency))
	}
	if n.options.RateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", n.options.RateLimit))
	}
	if n.options.Timeout > 0 {
		args = append(args, "-timeout", fmt.Sprintf("%d", n.options.Timeout))
	}
	if n.options.Retries > 0 {
		args = append(args, "-retries", fmt.Sprintf("%d", n.options.Retries))
	}
	for k, v := range req.Headers {
		args = append(args, "-H", fmt.Sprintf("%s: %s", k, v))
	}
	if req.Cookies != "" {
		args = append(args, "-H", "Cookie: "+req.Cookies)
	}
	if req.Proxy != "" {
		args = append(args, "-proxy", req.Proxy)
	}
	args = append(args, req.CustomArgs...)
	return args
}

// Execute runs Nuclei against the target and parses the JSONL output.
// Findings are populated incrementally; a non-nil error is returned only
// when the binary itself failed to run. Nuclei exits 0 even when zero
// findings are produced, so the absence of findings is not an error.
func (n *Nuclei) Execute(ctx context.Context, req *tools.ToolRequest) (*tools.ToolResult, error) {
	start := time.Now()
	result := tools.NewToolResult(n.Name())

	if !n.IsAvailable() {
		result.AddError("nuclei binary not found")
		return result, fmt.Errorf("nuclei not available")
	}

	cmd := exec.CommandContext(ctx, n.binaryPath, n.BuildArgs(req)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	result.ExecutionTime = time.Since(start)
	result.RawOutput = stdout.String()

	if runErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			result.AddError("execution timeout exceeded")
			return result, ctx.Err()
		}
		// Nuclei conventionally exits 0 on a clean run regardless of
		// whether findings were produced, and non-zero only on real
		// failure (bad templates, network, panic). Surface that as an
		// error but still attempt to parse anything that did emit.
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			result.AddError(fmt.Sprintf("nuclei exited with code %d: %s",
				exitErr.ExitCode(), strings.TrimSpace(stderr.String())))
		} else {
			result.AddError(fmt.Sprintf("nuclei run error: %v", runErr))
		}
	}

	for _, f := range ParseJSONL(result.RawOutput) {
		result.AddFinding(f)
	}
	return result, nil
}

// nucleiResult is the subset of the upstream JSONL schema we need to
// render a core.Finding. Fields we don't consume are dropped to keep
// the parser tolerant of upstream additions.
type nucleiResult struct {
	TemplateID  string `json:"template-id"`
	TemplateURL string `json:"template-url"`
	Type        string `json:"type"`
	Host        string `json:"host"`
	MatchedAt   string `json:"matched-at"`
	Request     string `json:"request"`
	Response    string `json:"response"`
	CURL        string `json:"curl-command"`
	Extracted   []string `json:"extracted-results"`
	Info        struct {
		Name           string   `json:"name"`
		Severity       string   `json:"severity"`
		Description    string   `json:"description"`
		Tags           []string `json:"tags"`
		Reference      []string `json:"reference"`
		Remediation    string   `json:"remediation"`
		Classification struct {
			CVEID    []string `json:"cve-id"`
			CWEID    []string `json:"cwe-id"`
			CVSSScore float64 `json:"cvss-score"`
		} `json:"classification"`
	} `json:"info"`
}

// ParseJSONL converts Nuclei's JSONL stdout into core.Finding entries.
// Malformed lines are silently skipped — Nuclei occasionally interleaves
// banners or warnings that the calling code should not treat as fatal.
func ParseJSONL(raw string) []*core.Finding {
	var out []*core.Finding
	if raw == "" {
		return out
	}
	sc := bufio.NewScanner(strings.NewReader(raw))
	// Some nuclei runs emit very long single-line JSON (large response
	// bodies); raise the scanner buffer to avoid token-too-long errors.
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] != '{' {
			continue
		}
		var nr nucleiResult
		if err := json.Unmarshal([]byte(line), &nr); err != nil {
			continue
		}
		if f := nucleiToFinding(&nr); f != nil {
			out = append(out, f)
		}
	}
	return out
}

// nucleiToFinding maps a parsed nuclei JSON record onto a core.Finding.
// Returns nil if the record is too sparse to be useful (no template ID
// and no name).
func nucleiToFinding(nr *nucleiResult) *core.Finding {
	if nr.TemplateID == "" && nr.Info.Name == "" {
		return nil
	}
	title := nr.Info.Name
	if title == "" {
		title = nr.TemplateID
	}
	sev := mapSeverity(nr.Info.Severity)
	// Use the template-id as the categorical Type and the human-readable
	// info.name as the Title — this matches how the rest of the codebase
	// renders findings (Type = stable identifier, Title = display name).
	typeName := nr.TemplateID
	if typeName == "" {
		typeName = title
	}
	f := core.NewFinding(typeName, sev)
	f.Title = title

	// Pick the most specific URL we have.
	switch {
	case nr.MatchedAt != "":
		f.URL = nr.MatchedAt
	case nr.Host != "":
		f.URL = nr.Host
	}

	f.Tool = "nuclei"
	f.Description = nr.Info.Description
	f.CWE = nr.Info.Classification.CWEID
	f.CVSS = nr.Info.Classification.CVSSScore
	f.References = append(f.References, nr.Info.Reference...)
	f.Remediation = nr.Info.Remediation
	if nr.Request != "" {
		f.Request = nr.Request
	}
	if nr.Response != "" {
		f.Response = nr.Response
	}
	if len(nr.Extracted) > 0 {
		f.Evidence = strings.Join(nr.Extracted, "\n")
	}

	// Stash everything that doesn't have a first-class field on Finding.
	if f.Metadata == nil {
		f.Metadata = make(map[string]interface{})
	}
	f.Metadata["nuclei.template-id"] = nr.TemplateID
	if nr.TemplateURL != "" {
		f.Metadata["nuclei.template-url"] = nr.TemplateURL
	}
	if len(nr.Info.Tags) > 0 {
		f.Metadata["nuclei.tags"] = nr.Info.Tags
	}
	if len(nr.Info.Classification.CVEID) > 0 {
		f.Metadata["nuclei.cve"] = nr.Info.Classification.CVEID
	}
	if nr.CURL != "" {
		f.Metadata["nuclei.curl"] = nr.CURL
	}
	if nr.Type != "" {
		f.Metadata["nuclei.protocol"] = nr.Type
	}
	return f
}

// mapSeverity converts the upstream severity string to core.Severity.
// Unknown values fall back to Info — Nuclei has occasionally added new
// severities (e.g., "unknown") and dropping the finding entirely would
// hide signal.
func mapSeverity(s string) core.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return core.SeverityCritical
	case "high":
		return core.SeverityHigh
	case "medium":
		return core.SeverityMedium
	case "low":
		return core.SeverityLow
	case "info", "informational":
		return core.SeverityInfo
	default:
		return core.SeverityInfo
	}
}

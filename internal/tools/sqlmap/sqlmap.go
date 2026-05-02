package sqlmap

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/tools"
)

// Options configures SQLMap execution parameters.
type Options struct {
	Level       int    // SQLMap level (1-5)
	Risk        int    // SQLMap risk (1-3)
	Threads     int    // Number of concurrent threads
	Technique   string // SQLMap techniques (BEUSTQ)
	DBMS        string // Target DBMS
	Tamper      string // Tamper script
	Verbose     int    // Verbosity level
	Timeout     int    // Request timeout in seconds
	Retries     int    // Number of retries
	Delay       int    // Delay between requests in seconds
	RandomAgent bool   // Use random User-Agent
}

// defaultOptions returns the default SQLMap options.
func defaultOptions() Options {
	return Options{
		Level:   1,
		Risk:    1,
		Threads: 1,
		Verbose: 1,
		Timeout: 30,
		Retries: 3,
	}
}

// SQLMap wraps the SQLMap tool for SQL injection testing.
type SQLMap struct {
	binaryPath string
	version    string
	options    Options
}

// New creates a new SQLMap instance.
func New() *SQLMap {
	s := &SQLMap{
		options: defaultOptions(),
	}
	s.findBinary()
	return s
}

// findBinary locates the SQLMap binary.
func (s *SQLMap) findBinary() {
	// Try direct sqlmap command first
	if path, err := exec.LookPath("sqlmap"); err == nil {
		s.binaryPath = path
		return
	}

	// Try common installation paths
	paths := []string{
		"/usr/bin/sqlmap",
		"/usr/local/bin/sqlmap",
		"/opt/sqlmap/sqlmap.py",
	}

	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			s.binaryPath = path
			return
		}
	}
}

// Name returns the tool name.
func (s *SQLMap) Name() string {
	return "sqlmap"
}

// Version returns the SQLMap version.
func (s *SQLMap) Version() string {
	if s.version != "" {
		return s.version
	}

	if !s.IsAvailable() {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.binaryPath, "--version")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	// Parse version from output
	re := regexp.MustCompile(`sqlmap\s+([0-9.]+)`)
	matches := re.FindStringSubmatch(string(output))
	if len(matches) > 1 {
		s.version = matches[1]
	}

	return s.version
}

// IsAvailable checks if SQLMap is available on the system.
func (s *SQLMap) IsAvailable() bool {
	return s.binaryPath != ""
}

// HealthCheck verifies SQLMap is working correctly.
func (s *SQLMap) HealthCheck() error {
	if !s.IsAvailable() {
		return fmt.Errorf("sqlmap binary not found")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.binaryPath, "--version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sqlmap health check failed: %w", err)
	}

	return nil
}

// WithOptions sets custom options.
func (s *SQLMap) WithOptions(opts Options) *SQLMap {
	s.options = opts
	return s
}

// Options returns the current options.
func (s *SQLMap) Options() Options {
	return s.options
}

// DefaultOptions returns the default options.
func (s *SQLMap) DefaultOptions() Options {
	return defaultOptions()
}

// BuildArgs builds command line arguments for SQLMap.
func (s *SQLMap) BuildArgs(req *tools.ToolRequest) []string {
	args := []string{
		"-u", req.Target,
		"--batch",
		fmt.Sprintf("--level=%d", s.options.Level),
		fmt.Sprintf("--risk=%d", s.options.Risk),
		fmt.Sprintf("--threads=%d", s.options.Threads),
	}

	// Add method if not GET
	if req.Method != "" && req.Method != "GET" {
		args = append(args, "--method", req.Method)
	}

	// Add POST data
	if req.Data != "" {
		args = append(args, "--data", req.Data)
	}

	// Add headers
	for name, value := range req.Headers {
		args = append(args, "-H", fmt.Sprintf("%s: %s", name, value))
	}

	// Add cookies
	if req.Cookies != "" {
		args = append(args, "--cookie", req.Cookies)
	}

	// Add proxy
	if req.Proxy != "" {
		args = append(args, "--proxy", req.Proxy)
	}

	// Add output directory
	if req.OutputDir != "" {
		args = append(args, "-o", req.OutputDir)
	}

	// Add technique if specified
	if s.options.Technique != "" {
		args = append(args, "--technique", s.options.Technique)
	}

	// Add DBMS if specified
	if s.options.DBMS != "" {
		args = append(args, "--dbms", s.options.DBMS)
	}

	// Add tamper scripts if specified
	if s.options.Tamper != "" {
		args = append(args, "--tamper", s.options.Tamper)
	}

	// Add random agent if enabled
	if s.options.RandomAgent {
		args = append(args, "--random-agent")
	}

	// Add custom arguments
	args = append(args, req.CustomArgs...)

	return args
}

// Execute runs SQLMap against the target.
func (s *SQLMap) Execute(ctx context.Context, req *tools.ToolRequest) (*tools.ToolResult, error) {
	start := time.Now()
	result := tools.NewToolResult(s.Name())

	if !s.IsAvailable() {
		result.AddError("sqlmap binary not found")
		return result, fmt.Errorf("sqlmap not available")
	}

	args := s.BuildArgs(req)

	// Create command with context
	cmd := exec.CommandContext(ctx, s.binaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Run the command
	err := cmd.Run()
	result.ExecutionTime = time.Since(start)
	result.RawOutput = stdout.String()

	if err != nil {
		// Check if it's a context timeout
		if ctx.Err() == context.DeadlineExceeded {
			result.AddError("execution timeout exceeded")
			return result, ctx.Err()
		}

		// Some "errors" from SQLMap are actually normal (exit code 1 = no vuln found)
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() != 0 && exitErr.ExitCode() != 1 {
				result.AddError(fmt.Sprintf("sqlmap exited with code %d: %s",
					exitErr.ExitCode(), stderr.String()))
			}
		}
	}

	// Parse the output for findings
	parsed := s.ParseOutput(result.RawOutput, req.Target)
	result.AddFindings(parsed.Findings)

	return result, nil
}

// ParseOutput parses SQLMap output and extracts findings.
func (s *SQLMap) ParseOutput(output, target string) *tools.ToolResult {
	result := tools.NewToolResult(s.Name())

	// Check for injection points
	if strings.Contains(output, "sqlmap identified the following injection point") {
		// Parse injection types and parameters
		findings := s.extractFindings(output, target)
		result.AddFindings(findings)
	}

	return result
}

// extractFindings extracts individual findings from SQLMap output.
func (s *SQLMap) extractFindings(output, target string) []*core.Finding {
	findings := make([]*core.Finding, 0)

	// Pattern to match parameter and type
	paramPattern := regexp.MustCompile(`Parameter:\s+(\w+)\s+\((\w+)\)`)
	typePattern := regexp.MustCompile(`Type:\s+(.+)`)
	payloadPattern := regexp.MustCompile(`Payload:\s+(.+)`)

	lines := strings.Split(output, "\n")
	var currentParam, currentMethod string

	for i, line := range lines {
		// Find parameter
		if matches := paramPattern.FindStringSubmatch(line); len(matches) > 2 {
			currentParam = matches[1]
			currentMethod = matches[2]
		}

		// Find injection type
		if matches := typePattern.FindStringSubmatch(line); len(matches) > 1 {
			injType := strings.TrimSpace(matches[1])

			// Look for payload in next few lines
			payload := ""
			for j := i + 1; j < len(lines) && j < i+5; j++ {
				if payloadMatches := payloadPattern.FindStringSubmatch(lines[j]); len(payloadMatches) > 1 {
					payload = strings.TrimSpace(payloadMatches[1])
					break
				}
			}

			finding := core.NewFinding("SQL Injection", s.determineSeverity(injType))
			finding.URL = target
			finding.Parameter = currentParam
			finding.Description = fmt.Sprintf("%s SQL Injection in %s parameter '%s'",
				injType, currentMethod, currentParam)
			finding.Evidence = payload
			finding.Tool = s.Name()

			// Add OWASP mappings
			finding.WithOWASPMapping(
				[]string{"WSTG-INPV-05"},
				[]string{"A03:2025"},
				[]string{"CWE-89"},
			)

			findings = append(findings, finding)
		}
	}

	// If we found injection but couldn't parse details, add generic finding
	if len(findings) == 0 && strings.Contains(output, "injectable") {
		finding := core.NewFinding("SQL Injection", core.SeverityHigh)
		finding.URL = target
		finding.Description = "SQL Injection vulnerability detected"
		finding.Tool = s.Name()
		finding.WithOWASPMapping(
			[]string{"WSTG-INPV-05"},
			[]string{"A03:2025"},
			[]string{"CWE-89"},
		)
		findings = append(findings, finding)
	}

	return findings
}

// determineSeverity determines finding severity based on injection type.
func (s *SQLMap) determineSeverity(injType string) core.Severity {
	injTypeLower := strings.ToLower(injType)

	// Union-based and stacked queries are most dangerous
	if strings.Contains(injTypeLower, "union") ||
		strings.Contains(injTypeLower, "stacked") {
		return core.SeverityCritical
	}

	// Error-based is highly reliable
	if strings.Contains(injTypeLower, "error-based") {
		return core.SeverityCritical
	}

	// Boolean and time-based are exploitable but slower
	if strings.Contains(injTypeLower, "boolean") ||
		strings.Contains(injTypeLower, "time-based") {
		return core.SeverityHigh
	}

	return core.SeverityHigh
}

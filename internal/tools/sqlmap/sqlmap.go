package sqlmap

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/tools"
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
	s := &SQLMap{options: defaultOptions()}
	s.findBinary()
	return s
}

func (s *SQLMap) findBinary() {
	if path, err := exec.LookPath("sqlmap"); err == nil {
		s.binaryPath = path
		return
	}
	for _, path := range []string{
		"/usr/bin/sqlmap",
		"/usr/local/bin/sqlmap",
		"/opt/sqlmap/sqlmap.py",
	} {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			s.binaryPath = path
			return
		}
	}
}

func (s *SQLMap) Name() string      { return "sqlmap" }
func (s *SQLMap) IsAvailable() bool { return s.binaryPath != "" }

func (s *SQLMap) Version() string {
	if s.version != "" {
		return s.version
	}
	if !s.IsAvailable() {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, s.binaryPath, "--version").Output()
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`sqlmap\s+([0-9.]+)`)
	if m := re.FindStringSubmatch(string(output)); len(m) > 1 {
		s.version = m[1]
	}
	return s.version
}

func (s *SQLMap) HealthCheck() error {
	if !s.IsAvailable() {
		return fmt.Errorf("sqlmap binary not found")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, s.binaryPath, "--version").Run()
}

// WithOptions sets custom options.
func (s *SQLMap) WithOptions(opts Options) *SQLMap {
	s.options = opts
	return s
}

// Options returns the current options.
func (s *SQLMap) Options() Options { return s.options }

// DefaultOptions returns the default options.
func (s *SQLMap) DefaultOptions() Options { return defaultOptions() }

// BuildArgs builds command line arguments for SQLMap.
func (s *SQLMap) BuildArgs(req *tools.ToolRequest) []string {
	autonomous := tools.IsAutonomous(req)

	args := []string{
		"-u", req.Target,
		"--batch",
		"--flush-session",
		fmt.Sprintf("--level=%d", s.options.Level),
		fmt.Sprintf("--risk=%d", s.options.Risk),
		fmt.Sprintf("--threads=%d", s.options.Threads),
		"--ignore-code=401",
	}

	// Autonomous mode: let sqlmap crawl and discover forms on its own.
	if autonomous {
		args = append(args, "--crawl=2", "--forms", "--smart")
	}

	if req.Method != "" && req.Method != "GET" {
		args = append(args, "--method", req.Method)
	}
	if req.Data != "" {
		args = append(args, "--data", req.Data)
	}
	for name, value := range req.Headers {
		args = append(args, "-H", fmt.Sprintf("%s: %s", name, value))
	}
	if req.Cookies != "" {
		args = append(args, "--cookie", req.Cookies)
	}
	if req.Proxy != "" {
		args = append(args, "--proxy", req.Proxy)
	}
	if req.OutputDir != "" {
		args = append(args, "--output-dir", req.OutputDir)
	}
	if s.options.Technique != "" {
		args = append(args, "--technique", s.options.Technique)
	}
	if s.options.DBMS != "" {
		args = append(args, "--dbms", s.options.DBMS)
	}
	if s.options.Tamper != "" {
		args = append(args, "--tamper", s.options.Tamper)
	}
	if s.options.RandomAgent {
		args = append(args, "--random-agent")
	}

	// Add custom arguments after validating against blocked flags.
	for _, a := range tools.StripInternalFlags(req.CustomArgs) {
		if isSQLMapBlockedFlag(a) {
			return nil
		}
		args = append(args, a)
	}
	return args
}

var sqlmapBlockedFlags = []string{
	"--os-shell", "--os-cmd", "--os-pwn", "--os-bof", "--os-smbrelay",
	"--file-read", "--file-write", "--file-dest",
	"--sql-shell", "--sql-query", "--sql-file",
	"--reg-read", "--reg-add", "--reg-del",
	"--priv-esc",
}

func isSQLMapBlockedFlag(arg string) bool {
	a := strings.SplitN(arg, "=", 2)[0]
	for _, b := range sqlmapBlockedFlags {
		if a == b {
			return true
		}
	}
	return false
}

// Execute runs SQLMap against the target.
func (s *SQLMap) Execute(ctx context.Context, req *tools.ToolRequest) (*tools.ToolResult, error) {
	start := time.Now()
	result := tools.NewToolResult(s.Name())

	if !s.IsAvailable() {
		result.AddError("sqlmap binary not found")
		return result, fmt.Errorf("sqlmap not available")
	}

	// Ensure output directory exists for log-file parsing.
	outDir := req.OutputDir
	if outDir == "" {
		outDir, _ = os.MkdirTemp("", "assay-sqlmap-*")
		defer os.RemoveAll(outDir)
		req.OutputDir = outDir
	}

	args := s.BuildArgs(req)
	if args == nil {
		result.AddError("blocked flag in custom args")
		return result, fmt.Errorf("blocked flag")
	}

	cmd := exec.CommandContext(ctx, s.binaryPath, args...)
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
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() != 0 && exitErr.ExitCode() != 1 {
				result.AddError(fmt.Sprintf("sqlmap exited with code %d: %s",
					exitErr.ExitCode(), stderr.String()))
			}
		}
	}

	// Parse the log file first (structured output), fall back to stdout.
	logContent := s.readLogFile(outDir)
	if logContent != "" {
		parsed := s.ParseOutput(logContent, req.Target)
		result.AddFindings(parsed.Findings)
	}
	if len(result.Findings) == 0 {
		parsed := s.ParseOutput(result.RawOutput, req.Target)
		result.AddFindings(parsed.Findings)
	}

	return result, nil
}

// readLogFile reads the sqlmap log file from the output directory.
// sqlmap writes to <output-dir>/<host>/log.
func (s *SQLMap) readLogFile(outDir string) string {
	// Walk the output dir to find any "log" file.
	var logContent string
	_ = filepath.Walk(outDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.Name() == "log" && !info.IsDir() {
			data, readErr := os.ReadFile(path)
			if readErr == nil {
				logContent = string(data)
				return filepath.SkipAll
			}
		}
		return nil
	})
	return logContent
}

// ParseOutput parses SQLMap output (from log file or stdout).
func (s *SQLMap) ParseOutput(output, target string) *tools.ToolResult {
	result := tools.NewToolResult(s.Name())

	if strings.Contains(output, "sqlmap identified the following injection point") ||
		strings.Contains(output, "is injectable") ||
		strings.Contains(output, "are injectable") {
		findings := s.extractFindings(output, target)
		result.AddFindings(findings)
	}

	return result
}

func (s *SQLMap) extractFindings(output, target string) []*core.Finding {
	var findings []*core.Finding

	// Real sqlmap log format:
	// Parameter: JSON username ((custom) POST)
	//     Type: error-based
	//     Title: PostgreSQL AND error-based ...
	//     Payload: {"username":"test' AND ..."}
	paramPattern := regexp.MustCompile(`Parameter:\s+(.+?)\s+\((.+?)\)`)
	typePattern := regexp.MustCompile(`^\s+Type:\s+(.+)`)
	titlePattern := regexp.MustCompile(`^\s+Title:\s+(.+)`)
	payloadPattern := regexp.MustCompile(`^\s+Payload:\s+(.+)`)
	dbmsPattern := regexp.MustCompile(`back-end DBMS:\s+(.+)`)

	lines := strings.Split(output, "\n")
	var currentParam, currentPlace, dbms string

	for i, line := range lines {
		if m := paramPattern.FindStringSubmatch(line); len(m) > 2 {
			currentParam = m[1]
			currentPlace = m[2]
		}

		if m := dbmsPattern.FindStringSubmatch(line); len(m) > 1 {
			dbms = strings.TrimSpace(m[1])
		}

		if m := typePattern.FindStringSubmatch(line); len(m) > 1 {
			injType := strings.TrimSpace(m[1])
			title := ""
			payload := ""

			// Look ahead for Title and Payload.
			for j := i + 1; j < len(lines) && j < i+6; j++ {
				if tm := titlePattern.FindStringSubmatch(lines[j]); len(tm) > 1 {
					title = strings.TrimSpace(tm[1])
				}
				if pm := payloadPattern.FindStringSubmatch(lines[j]); len(pm) > 1 {
					payload = strings.TrimSpace(pm[1])
					break
				}
			}

			finding := core.NewFinding("SQL Injection", s.determineSeverity(injType))
			finding.URL = target
			finding.Parameter = currentParam

			desc := fmt.Sprintf("%s SQL Injection in %s parameter '%s'", injType, currentPlace, currentParam)
			if title != "" {
				desc += ": " + title
			}
			if dbms != "" {
				desc += " (DBMS: " + dbms + ")"
			}
			finding.Description = desc
			finding.Evidence = payload
			finding.Tool = s.Name()
			finding.WithOWASPMapping(
				[]string{"WSTG-INPV-05"},
				[]string{"A05:2025"},
				[]string{"CWE-89"},
			)
			findings = append(findings, finding)
		}
	}

	// Fallback: sqlmap said "injectable" but we couldn't parse detail blocks.
	if len(findings) == 0 && strings.Contains(output, "injectable") {
		finding := core.NewFinding("SQL Injection", core.SeverityHigh)
		finding.URL = target
		finding.Description = "SQL Injection detected by sqlmap"
		finding.Tool = s.Name()
		finding.WithOWASPMapping(
			[]string{"WSTG-INPV-05"},
			[]string{"A05:2025"},
			[]string{"CWE-89"},
		)
		findings = append(findings, finding)
	}

	return findings
}

func (s *SQLMap) determineSeverity(injType string) core.Severity {
	lower := strings.ToLower(injType)
	if strings.Contains(lower, "union") || strings.Contains(lower, "stacked") {
		return core.SeverityCritical
	}
	if strings.Contains(lower, "error-based") {
		return core.SeverityCritical
	}
	return core.SeverityHigh
}

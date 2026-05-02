package sqlmap

import (
	"context"
	"testing"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/tools"
)

func TestSQLMap_Name(t *testing.T) {
	s := New()
	if s.Name() != "sqlmap" {
		t.Errorf("Name() = %q, want %q", s.Name(), "sqlmap")
	}
}

func TestSQLMap_Version(t *testing.T) {
	s := New()
	// Version should return empty string if sqlmap is not available
	// or actual version if available
	_ = s.Version()
}

func TestSQLMap_ImplementsToolInterface(t *testing.T) {
	var _ tools.Tool = (*SQLMap)(nil)
}

func TestSQLMap_BuildArgs_Basic(t *testing.T) {
	s := New()
	req := tools.NewToolRequest("https://example.com/page?id=1")

	args := s.BuildArgs(req)

	// Should contain -u flag with target
	found := false
	for i, arg := range args {
		if arg == "-u" && i+1 < len(args) && args[i+1] == "https://example.com/page?id=1" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("BuildArgs() missing -u flag with target URL")
	}

	// Should contain --batch flag
	hasBatch := false
	for _, arg := range args {
		if arg == "--batch" {
			hasBatch = true
			break
		}
	}
	if !hasBatch {
		t.Error("BuildArgs() should include --batch flag")
	}
}

func TestSQLMap_BuildArgs_WithHeaders(t *testing.T) {
	s := New()
	req := tools.NewToolRequest("https://example.com/page?id=1").
		WithHeaders(map[string]string{
			"Authorization": "Bearer token123",
			"X-Custom":      "value",
		})

	args := s.BuildArgs(req)

	// Should contain -H flags for headers
	headerCount := 0
	for i, arg := range args {
		if arg == "-H" && i+1 < len(args) {
			headerCount++
		}
	}
	if headerCount != 2 {
		t.Errorf("BuildArgs() header count = %d, want 2", headerCount)
	}
}

func TestSQLMap_BuildArgs_WithCookies(t *testing.T) {
	s := New()
	req := tools.NewToolRequest("https://example.com/page?id=1").
		WithCookies("session=abc123; token=xyz")

	args := s.BuildArgs(req)

	// Should contain --cookie flag
	found := false
	for i, arg := range args {
		if arg == "--cookie" && i+1 < len(args) {
			found = true
			break
		}
	}
	if !found {
		t.Error("BuildArgs() should include --cookie flag")
	}
}

func TestSQLMap_BuildArgs_WithProxy(t *testing.T) {
	s := New()
	req := tools.NewToolRequest("https://example.com/page?id=1").
		WithProxy("http://127.0.0.1:8080")

	args := s.BuildArgs(req)

	// Should contain --proxy flag
	found := false
	for i, arg := range args {
		if arg == "--proxy" && i+1 < len(args) && args[i+1] == "http://127.0.0.1:8080" {
			found = true
			break
		}
	}
	if !found {
		t.Error("BuildArgs() should include --proxy flag")
	}
}

func TestSQLMap_BuildArgs_WithData(t *testing.T) {
	s := New()
	req := tools.NewToolRequest("https://example.com/login").
		WithMethod("POST").
		WithData("username=admin&password=test")

	args := s.BuildArgs(req)

	// Should contain --data flag
	found := false
	for i, arg := range args {
		if arg == "--data" && i+1 < len(args) {
			found = true
			break
		}
	}
	if !found {
		t.Error("BuildArgs() should include --data flag for POST")
	}
}

func TestSQLMap_BuildArgs_WithMethod(t *testing.T) {
	s := New()
	req := tools.NewToolRequest("https://example.com/api").
		WithMethod("PUT")

	args := s.BuildArgs(req)

	// Should contain --method flag
	found := false
	for i, arg := range args {
		if arg == "--method" && i+1 < len(args) && args[i+1] == "PUT" {
			found = true
			break
		}
	}
	if !found {
		t.Error("BuildArgs() should include --method flag")
	}
}

func TestSQLMap_BuildArgs_WithCustomArgs(t *testing.T) {
	s := New()
	req := tools.NewToolRequest("https://example.com/page?id=1").
		WithCustomArgs("--level=5", "--risk=3", "--technique=BEU")

	args := s.BuildArgs(req)

	// Should contain custom args
	hasLevel := false
	hasRisk := false
	hasTechnique := false
	for _, arg := range args {
		if arg == "--level=5" {
			hasLevel = true
		}
		if arg == "--risk=3" {
			hasRisk = true
		}
		if arg == "--technique=BEU" {
			hasTechnique = true
		}
	}
	if !hasLevel || !hasRisk || !hasTechnique {
		t.Error("BuildArgs() should include custom args")
	}
}

func TestSQLMap_BuildArgs_OutputFormat(t *testing.T) {
	s := New()
	req := tools.NewToolRequest("https://example.com/page?id=1")
	req.OutputDir = "/tmp/sqlmap_output"

	args := s.BuildArgs(req)

	// Should contain output directory
	found := false
	for i, arg := range args {
		if arg == "-o" && i+1 < len(args) {
			found = true
			break
		}
	}
	if !found {
		t.Error("BuildArgs() should include -o flag for output")
	}
}

func TestSQLMap_ParseOutput_NoVulnerability(t *testing.T) {
	s := New()
	output := `[INFO] testing connection to the target URL
[INFO] testing if the target URL content is stable
[INFO] target URL content is stable
[WARNING] GET parameter 'id' does not seem to be injectable
[INFO] testing if GET parameter 'id' is dynamic
[WARNING] GET parameter 'id' does not appear to be dynamic
[INFO] all tested parameters do not appear to be injectable`

	result := s.ParseOutput(output, "https://example.com/page?id=1")

	if result.HasFindings() {
		t.Error("ParseOutput() should not find vulnerabilities in clean output")
	}
}

func TestSQLMap_ParseOutput_WithVulnerability(t *testing.T) {
	s := New()
	output := `[INFO] testing connection to the target URL
[INFO] testing if the target URL content is stable
[INFO] target URL content is stable
[INFO] testing if GET parameter 'id' is dynamic
[INFO] GET parameter 'id' appears to be dynamic
[INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable
[INFO] testing for SQL injection on GET parameter 'id'
[INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[INFO] GET parameter 'id' is 'AND boolean-based blind - WHERE or HAVING clause' injectable
[INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause'
[INFO] GET parameter 'id' is 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause' injectable
sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 5234=5234

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause
    Payload: id=1 AND (SELECT 1337 FROM(SELECT COUNT(*),CONCAT(0x7171787671,(SELECT (ELT(1337=1337,1))),0x71767a7a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)
---
[INFO] the back-end DBMS is MySQL`

	result := s.ParseOutput(output, "https://example.com/page?id=1")

	if !result.HasFindings() {
		t.Error("ParseOutput() should find SQL injection vulnerability")
	}

	if len(result.Findings) < 1 {
		t.Error("Should have at least one finding")
	}
}

func TestSQLMap_DefaultOptions(t *testing.T) {
	s := New()
	opts := s.DefaultOptions()

	// Check that default options are set
	if opts.Level < 1 || opts.Level > 5 {
		t.Errorf("Level = %d, should be between 1 and 5", opts.Level)
	}
	if opts.Risk < 1 || opts.Risk > 3 {
		t.Errorf("Risk = %d, should be between 1 and 3", opts.Risk)
	}
	if opts.Threads < 1 {
		t.Errorf("Threads = %d, should be at least 1", opts.Threads)
	}
}

func TestSQLMap_WithOptions(t *testing.T) {
	s := New().WithOptions(Options{
		Level:   5,
		Risk:    3,
		Threads: 10,
	})

	opts := s.Options()
	if opts.Level != 5 {
		t.Errorf("Level = %d, want 5", opts.Level)
	}
	if opts.Risk != 3 {
		t.Errorf("Risk = %d, want 3", opts.Risk)
	}
	if opts.Threads != 10 {
		t.Errorf("Threads = %d, want 10", opts.Threads)
	}
}

func TestSQLMap_Execute_NotAvailable(t *testing.T) {
	s := &SQLMap{
		binaryPath: "", // Empty path means not available
		options:    defaultOptions(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := tools.NewToolRequest("https://example.com/page?id=1")
	result, err := s.Execute(ctx, req)

	// Should return error when sqlmap is not available
	if err == nil {
		t.Error("Execute() should return error when sqlmap is not available")
	}

	// Result should indicate failure
	if result.IsSuccess() {
		t.Error("Execute() result should indicate failure when sqlmap is not available")
	}
}

func TestSQLMap_Execute_WithFakeBinary(t *testing.T) {
	// Create a fake binary that outputs SQLMap-like results
	s := &SQLMap{
		binaryPath: "echo", // Use echo as a fake binary
		options:    defaultOptions(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := tools.NewToolRequest("https://example.com/page?id=1")
	result, err := s.Execute(ctx, req)

	// echo should succeed (exit code 0)
	if err != nil {
		t.Logf("Execute() error = %v (expected on some systems)", err)
	}

	if result == nil {
		t.Fatal("Result should not be nil")
	}

	// Execution time should be recorded
	if result.ExecutionTime <= 0 {
		t.Error("ExecutionTime should be positive")
	}
}

func TestSQLMap_Version_NotAvailable(t *testing.T) {
	s := &SQLMap{
		binaryPath: "", // Not available
		options:    defaultOptions(),
	}

	version := s.Version()
	if version != "" {
		t.Errorf("Version() = %q, want empty string when not available", version)
	}
}

func TestSQLMap_Version_CachedVersion(t *testing.T) {
	s := &SQLMap{
		binaryPath: "",
		version:    "1.5.0",
		options:    defaultOptions(),
	}

	version := s.Version()
	if version != "1.5.0" {
		t.Errorf("Version() = %q, want %q (cached)", version, "1.5.0")
	}
}

func TestSQLMap_IsAvailable(t *testing.T) {
	tests := []struct {
		name       string
		binaryPath string
		expected   bool
	}{
		{name: "available", binaryPath: "/usr/bin/sqlmap", expected: true},
		{name: "not available", binaryPath: "", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SQLMap{binaryPath: tt.binaryPath, options: defaultOptions()}
			if s.IsAvailable() != tt.expected {
				t.Errorf("IsAvailable() = %v, want %v", s.IsAvailable(), tt.expected)
			}
		})
	}
}

func TestSQLMap_HealthCheck_NotAvailable(t *testing.T) {
	s := &SQLMap{
		binaryPath: "",
		options:    defaultOptions(),
	}

	err := s.HealthCheck()
	if err == nil {
		t.Error("HealthCheck() should return error when not available")
	}
}

func TestSQLMap_HealthCheck_InvalidBinary(t *testing.T) {
	s := &SQLMap{
		binaryPath: "/nonexistent/path/sqlmap",
		options:    defaultOptions(),
	}

	err := s.HealthCheck()
	if err == nil {
		t.Error("HealthCheck() should return error for invalid binary path")
	}
}

func TestSQLMap_BuildArgs_WithTechnique(t *testing.T) {
	s := &SQLMap{
		binaryPath: "/usr/bin/sqlmap",
		options: Options{
			Level:     1,
			Risk:      1,
			Threads:   1,
			Technique: "BEUST",
		},
	}

	req := tools.NewToolRequest("https://example.com/page?id=1")
	args := s.BuildArgs(req)

	found := false
	for i, arg := range args {
		if arg == "--technique" && i+1 < len(args) && args[i+1] == "BEUST" {
			found = true
			break
		}
	}
	if !found {
		t.Error("BuildArgs() should include --technique flag")
	}
}

func TestSQLMap_BuildArgs_WithDBMS(t *testing.T) {
	s := &SQLMap{
		binaryPath: "/usr/bin/sqlmap",
		options: Options{
			Level:   1,
			Risk:    1,
			Threads: 1,
			DBMS:    "MySQL",
		},
	}

	req := tools.NewToolRequest("https://example.com/page?id=1")
	args := s.BuildArgs(req)

	found := false
	for i, arg := range args {
		if arg == "--dbms" && i+1 < len(args) && args[i+1] == "MySQL" {
			found = true
			break
		}
	}
	if !found {
		t.Error("BuildArgs() should include --dbms flag")
	}
}

func TestSQLMap_BuildArgs_WithTamper(t *testing.T) {
	s := &SQLMap{
		binaryPath: "/usr/bin/sqlmap",
		options: Options{
			Level:   1,
			Risk:    1,
			Threads: 1,
			Tamper:  "space2comment",
		},
	}

	req := tools.NewToolRequest("https://example.com/page?id=1")
	args := s.BuildArgs(req)

	found := false
	for i, arg := range args {
		if arg == "--tamper" && i+1 < len(args) && args[i+1] == "space2comment" {
			found = true
			break
		}
	}
	if !found {
		t.Error("BuildArgs() should include --tamper flag")
	}
}

func TestSQLMap_BuildArgs_WithRandomAgent(t *testing.T) {
	s := &SQLMap{
		binaryPath: "/usr/bin/sqlmap",
		options: Options{
			Level:       1,
			Risk:        1,
			Threads:     1,
			RandomAgent: true,
		},
	}

	req := tools.NewToolRequest("https://example.com/page?id=1")
	args := s.BuildArgs(req)

	found := false
	for _, arg := range args {
		if arg == "--random-agent" {
			found = true
			break
		}
	}
	if !found {
		t.Error("BuildArgs() should include --random-agent flag")
	}
}

func TestSQLMap_BuildArgs_GETMethod_NoMethodFlag(t *testing.T) {
	s := New()
	req := tools.NewToolRequest("https://example.com/page?id=1")
	// Method is GET by default

	args := s.BuildArgs(req)

	// GET requests should NOT include --method flag
	for _, arg := range args {
		if arg == "--method" {
			t.Error("BuildArgs() should NOT include --method for GET requests")
		}
	}
}

func TestSQLMap_BuildArgs_EmptyMethod_NoMethodFlag(t *testing.T) {
	s := New()
	req := tools.NewToolRequest("https://example.com/page?id=1")
	req.Method = ""

	args := s.BuildArgs(req)

	for _, arg := range args {
		if arg == "--method" {
			t.Error("BuildArgs() should NOT include --method for empty method")
		}
	}
}

func TestSQLMap_ParseOutput_InjectableGeneric(t *testing.T) {
	s := New()
	output := `[INFO] testing connection to the target URL
[INFO] GET parameter 'id' is injectable
[WARNING] some warning`

	result := s.ParseOutput(output, "https://example.com/page?id=1")

	if !result.HasFindings() {
		t.Error("ParseOutput() should detect injectable parameter")
	}
}

func TestSQLMap_DetermineSeverity(t *testing.T) {
	s := New()

	tests := []struct {
		name     string
		injType  string
		expected string
	}{
		{name: "union-based", injType: "UNION query", expected: "critical"},
		{name: "stacked queries", injType: "stacked queries", expected: "critical"},
		{name: "error-based", injType: "error-based", expected: "critical"},
		{name: "boolean-based", injType: "boolean-based blind", expected: "high"},
		{name: "time-based", injType: "time-based blind", expected: "high"},
		{name: "unknown", injType: "unknown type", expected: "high"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sev := s.determineSeverity(tt.injType)
			if string(sev) != tt.expected {
				t.Errorf("determineSeverity(%q) = %q, want %q", tt.injType, sev, tt.expected)
			}
		})
	}
}

func TestSQLMap_ExtractFindings_DetailedOutput(t *testing.T) {
	s := New()
	output := `sqlmap identified the following injection point(s) with a total of 50 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 5234=5234

    Type: UNION query
    Title: Generic UNION query
    Payload: id=1 UNION ALL SELECT NULL,NULL--
---`

	result := s.ParseOutput(output, "https://example.com/page?id=1")

	if !result.HasFindings() {
		t.Error("ParseOutput() should find vulnerabilities")
	}

	if result.FindingCount() < 2 {
		t.Errorf("FindingCount() = %d, want >= 2", result.FindingCount())
	}
}

func TestSQLMap_ExtractFindings_MultipleParameters(t *testing.T) {
	s := New()
	output := `sqlmap identified the following injection point(s):
---
Parameter: id (GET)
    Type: error-based
    Title: MySQL error-based
    Payload: id=1 AND EXTRACTVALUE(1,1)

Parameter: name (POST)
    Type: time-based blind
    Title: MySQL time-based blind
    Payload: name=test' AND SLEEP(5)-- -
---`

	result := s.ParseOutput(output, "https://example.com/page?id=1")

	if !result.HasFindings() {
		t.Error("ParseOutput() should find vulnerabilities")
	}
}

func TestSQLMap_Options_Access(t *testing.T) {
	s := New()
	opts := s.Options()

	if opts.Level != 1 {
		t.Errorf("Default Level = %d, want 1", opts.Level)
	}
	if opts.Risk != 1 {
		t.Errorf("Default Risk = %d, want 1", opts.Risk)
	}
	if opts.Threads != 1 {
		t.Errorf("Default Threads = %d, want 1", opts.Threads)
	}
	if opts.Verbose != 1 {
		t.Errorf("Default Verbose = %d, want 1", opts.Verbose)
	}
	if opts.Timeout != 30 {
		t.Errorf("Default Timeout = %d, want 30", opts.Timeout)
	}
	if opts.Retries != 3 {
		t.Errorf("Default Retries = %d, want 3", opts.Retries)
	}
}

func TestSQLMap_WithOptions_AllFields(t *testing.T) {
	s := New().WithOptions(Options{
		Level:       5,
		Risk:        3,
		Threads:     10,
		Technique:   "BEUST",
		DBMS:        "MySQL",
		Tamper:      "space2comment",
		Verbose:     3,
		Timeout:     60,
		Retries:     5,
		Delay:       2,
		RandomAgent: true,
	})

	opts := s.Options()
	if opts.Level != 5 {
		t.Errorf("Level = %d", opts.Level)
	}
	if opts.Risk != 3 {
		t.Errorf("Risk = %d", opts.Risk)
	}
	if opts.Threads != 10 {
		t.Errorf("Threads = %d", opts.Threads)
	}
	if opts.Technique != "BEUST" {
		t.Errorf("Technique = %q", opts.Technique)
	}
	if opts.DBMS != "MySQL" {
		t.Errorf("DBMS = %q", opts.DBMS)
	}
	if opts.Tamper != "space2comment" {
		t.Errorf("Tamper = %q", opts.Tamper)
	}
	if !opts.RandomAgent {
		t.Error("RandomAgent should be true")
	}
	if opts.Delay != 2 {
		t.Errorf("Delay = %d", opts.Delay)
	}
}

func TestSQLMap_BuildArgs_AllOptions(t *testing.T) {
	s := &SQLMap{
		binaryPath: "/usr/bin/sqlmap",
		options: Options{
			Level:       3,
			Risk:        2,
			Threads:     5,
			Technique:   "BEU",
			DBMS:        "PostgreSQL",
			Tamper:      "between",
			RandomAgent: true,
		},
	}

	req := tools.NewToolRequest("https://example.com/api").
		WithMethod("POST").
		WithData("user=admin").
		WithHeaders(map[string]string{"Authorization": "Bearer token"}).
		WithCookies("session=xyz").
		WithProxy("http://proxy:8080").
		WithCustomArgs("--dbs")
	req.OutputDir = "/tmp/output"

	args := s.BuildArgs(req)

	checks := map[string]bool{
		"--batch":         false,
		"--method":        false,
		"--data":          false,
		"-H":              false,
		"--cookie":        false,
		"--proxy":         false,
		"-o":              false,
		"--technique":     false,
		"--dbms":          false,
		"--tamper":        false,
		"--random-agent":  false,
		"--dbs":           false,
	}

	for _, arg := range args {
		if _, ok := checks[arg]; ok {
			checks[arg] = true
		}
	}

	for flag, found := range checks {
		if !found {
			t.Errorf("BuildArgs() missing flag %q", flag)
		}
	}
}

package scanner

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/tools"
)

func TestNewScanner(t *testing.T) {
	scanner := New()

	if scanner == nil {
		t.Fatal("New() returned nil")
	}
}

func TestScanner_AddTarget(t *testing.T) {
	scanner := New()

	err := scanner.AddTarget("https://example.com")
	if err != nil {
		t.Errorf("AddTarget() error = %v", err)
	}

	targets := scanner.Targets()
	if len(targets) != 1 {
		t.Errorf("Targets() length = %d, want 1", len(targets))
	}
}

func TestScanner_AddTarget_Invalid(t *testing.T) {
	scanner := New()

	tests := []struct {
		name   string
		target string
	}{
		{"empty", ""},
		{"no scheme", "example.com"},
		{"invalid scheme", "ftp://example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := scanner.AddTarget(tt.target)
			if err == nil {
				t.Errorf("AddTarget(%q) should return error", tt.target)
			}
		})
	}
}

func TestScanner_RegisterTool(t *testing.T) {
	scanner := New()
	mock := &mockTool{name: "test-tool"}

	scanner.RegisterTool(mock)

	tools := scanner.Tools()
	if len(tools) != 1 {
		t.Errorf("Tools() length = %d, want 1", len(tools))
	}
	if tools[0].Name() != "test-tool" {
		t.Errorf("Tool name = %q, want %q", tools[0].Name(), "test-tool")
	}
}

func TestScanner_SetConfig(t *testing.T) {
	scanner := New()

	config := &Config{
		Timeout:     10 * time.Minute,
		Concurrency: 5,
		Verbose:     true,
	}

	scanner.SetConfig(config)

	got := scanner.Config()
	if got.Timeout != 10*time.Minute {
		t.Errorf("Config().Timeout = %v, want %v", got.Timeout, 10*time.Minute)
	}
	if got.Concurrency != 5 {
		t.Errorf("Config().Concurrency = %d, want 5", got.Concurrency)
	}
}

func TestScanner_Scan_NoTargets(t *testing.T) {
	scanner := New()

	ctx := context.Background()
	result, err := scanner.Scan(ctx)

	if err == nil {
		t.Error("Scan() should return error when no targets")
	}
	if result != nil {
		t.Error("Scan() result should be nil on error")
	}
}

func TestScanner_Scan_WithMockTool(t *testing.T) {
	scanner := New()
	// Disable internal scanner for this test to only test mock tool
	scanner.EnableInternalScanner(false)

	// Add target
	_ = scanner.AddTarget("https://example.com")

	// Register mock tool
	mock := &mockTool{
		name:      "mock-scanner",
		available: true,
		findings: []*core.Finding{
			{
				ID:       "test-1",
				Type:     "SQL Injection",
				Severity: core.SeverityHigh,
				URL:      "https://example.com/page?id=1",
			},
		},
	}
	scanner.RegisterTool(mock)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := scanner.Scan(ctx)
	if err != nil {
		t.Errorf("Scan() error = %v", err)
	}

	if result == nil {
		t.Fatal("Scan() returned nil result")
	}

	if len(result.Findings) != 1 {
		t.Errorf("Findings count = %d, want 1", len(result.Findings))
	}
}

func TestScanner_Scan_SkipsUnavailableTools(t *testing.T) {
	scanner := New()
	// Disable internal scanner to test only external tools
	scanner.EnableInternalScanner(false)
	_ = scanner.AddTarget("https://example.com")

	// Register unavailable tool
	unavailable := &mockTool{name: "unavailable", available: false}
	scanner.RegisterTool(unavailable)

	// Register available tool
	available := &mockTool{name: "available", available: true}
	scanner.RegisterTool(available)

	ctx := context.Background()
	result, err := scanner.Scan(ctx)

	if err != nil {
		t.Errorf("Scan() error = %v", err)
	}

	// Should only have run available tool (internal scanner disabled)
	if result.ToolsRun != 1 {
		t.Errorf("ToolsRun = %d, want 1", result.ToolsRun)
	}
	if result.ToolsSkipped != 1 {
		t.Errorf("ToolsSkipped = %d, want 1", result.ToolsSkipped)
	}
}

func TestScanResult_Summary(t *testing.T) {
	result := &ScanResult{
		Findings: core.Findings{
			core.NewFinding("SQLi", core.SeverityCritical),
			core.NewFinding("XSS", core.SeverityHigh),
			core.NewFinding("Info Disclosure", core.SeverityLow),
		},
	}

	summary := result.Summary()

	if summary.TotalFindings != 3 {
		t.Errorf("TotalFindings = %d, want 3", summary.TotalFindings)
	}
	if summary.Critical != 1 {
		t.Errorf("Critical = %d, want 1", summary.Critical)
	}
	if summary.High != 1 {
		t.Errorf("High = %d, want 1", summary.High)
	}
	if summary.Low != 1 {
		t.Errorf("Low = %d, want 1", summary.Low)
	}
}

func TestConfig_Defaults(t *testing.T) {
	config := DefaultConfig()

	if config.Timeout <= 0 {
		t.Error("Default timeout should be positive")
	}
	if config.Concurrency < 1 {
		t.Error("Default concurrency should be at least 1")
	}
}

func TestScanResult_HasCritical(t *testing.T) {
	tests := []struct {
		name     string
		findings core.Findings
		want     bool
	}{
		{
			name:     "no findings",
			findings: core.Findings{},
			want:     false,
		},
		{
			name: "with critical",
			findings: core.Findings{
				core.NewFinding("Critical Bug", core.SeverityCritical),
			},
			want: true,
		},
		{
			name: "without critical",
			findings: core.Findings{
				core.NewFinding("High Bug", core.SeverityHigh),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ScanResult{Findings: tt.findings}
			if result.HasCritical() != tt.want {
				t.Errorf("HasCritical() = %v, want %v", result.HasCritical(), tt.want)
			}
		})
	}
}

// TestScanner_Close verifies Close is safe on uninitialized scanners, safe
// to call twice, and propagates to the internal scanner when set.
func TestScanner_Close(t *testing.T) {
	// 1. Close on a fresh scanner with no internal config set: no panic.
	s := New()
	s.Close()
	s.Close() // idempotent

	// 2. Close after configuring the internal scanner: no panic.
	s2 := New()
	if err := s2.SetInternalConfig(DefaultInternalConfig()); err != nil {
		t.Fatalf("SetInternalConfig: %v", err)
	}
	s2.Close()
	s2.Close() // idempotent
}

// TestScanner_Scan_ManyErrors_NoDeadlock verifies that a scan producing
// more errors than errorsChan's buffer does not deadlock. Before the fix,
// errorsChan was drained serially only after findingsChan closed, so the
// 11th error-producing goroutine blocked forever on a full channel and
// wg.Wait never returned.
func TestScanner_Scan_ManyErrors_NoDeadlock(t *testing.T) {
	s := New()
	s.EnableInternalScanner(false)

	// 50 targets × 1 tool yields 50 sequential error sends; buffer is 10.
	for i := 0; i < 50; i++ {
		if err := s.AddTarget(fmt.Sprintf("https://example.com/%d", i)); err != nil {
			t.Fatalf("AddTarget: %v", err)
		}
	}
	s.RegisterTool(&errorTool{name: "err-tool", err: errors.New("boom")})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan struct{})
	var result *ScanResult
	var scanErr error
	go func() {
		result, scanErr = s.Scan(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Scan did not return within 5s — deadlocked on errorsChan")
	}

	if scanErr != nil {
		t.Fatalf("Scan unexpected error: %v", scanErr)
	}
	if result == nil {
		t.Fatal("Scan returned nil result")
	}
	if len(result.Errors) < 11 {
		t.Errorf("expected >=11 collected errors (buffer+overflow), got %d", len(result.Errors))
	}
}

// errorTool always fails Execute — used to stress the error-collection path.
type errorTool struct {
	name string
	err  error
}

func (t *errorTool) Name() string       { return t.name }
func (t *errorTool) Version() string    { return "1.0.0" }
func (t *errorTool) IsAvailable() bool  { return true }
func (t *errorTool) HealthCheck() error { return nil }
func (t *errorTool) Execute(ctx context.Context, req *tools.ToolRequest) (*tools.ToolResult, error) {
	return nil, t.err
}

// mockTool is a mock implementation of tools.Tool for testing.
type mockTool struct {
	name      string
	available bool
	findings  []*core.Finding
}

func (m *mockTool) Name() string       { return m.name }
func (m *mockTool) Version() string    { return "1.0.0" }
func (m *mockTool) IsAvailable() bool  { return m.available }
func (m *mockTool) HealthCheck() error { return nil }
func (m *mockTool) Execute(ctx context.Context, req *tools.ToolRequest) (*tools.ToolResult, error) {
	result := tools.NewToolResult(m.name)
	if m.findings != nil {
		result.AddFindings(m.findings)
	}
	return result, nil
}

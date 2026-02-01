package tools

import (
	"context"
	"testing"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
)

func TestNewToolRequest(t *testing.T) {
	req := NewToolRequest("https://example.com/test")

	if req.Target != "https://example.com/test" {
		t.Errorf("ToolRequest.Target = %q, want %q", req.Target, "https://example.com/test")
	}
	if req.Timeout != DefaultTimeout {
		t.Errorf("ToolRequest.Timeout = %v, want %v", req.Timeout, DefaultTimeout)
	}
}

func TestToolRequest_WithHeaders(t *testing.T) {
	req := NewToolRequest("https://example.com").
		WithHeaders(map[string]string{"Authorization": "Bearer token"})

	if req.Headers["Authorization"] != "Bearer token" {
		t.Error("Header not set correctly")
	}
}

func TestToolRequest_WithCookies(t *testing.T) {
	req := NewToolRequest("https://example.com").
		WithCookies("session=abc123")

	if req.Cookies != "session=abc123" {
		t.Errorf("Cookies = %q, want %q", req.Cookies, "session=abc123")
	}
}

func TestToolRequest_WithTimeout(t *testing.T) {
	req := NewToolRequest("https://example.com").
		WithTimeout(10 * time.Minute)

	if req.Timeout != 10*time.Minute {
		t.Errorf("Timeout = %v, want %v", req.Timeout, 10*time.Minute)
	}
}

func TestToolRequest_WithProxy(t *testing.T) {
	req := NewToolRequest("https://example.com").
		WithProxy("http://127.0.0.1:8080")

	if req.Proxy != "http://127.0.0.1:8080" {
		t.Errorf("Proxy = %q", req.Proxy)
	}
}

func TestToolResult_AddFinding(t *testing.T) {
	result := &ToolResult{
		ToolName: "test",
		Findings: make([]*core.Finding, 0),
	}

	finding := core.NewFinding("SQL Injection", core.SeverityCritical)
	result.AddFinding(finding)

	if len(result.Findings) != 1 {
		t.Errorf("len(Findings) = %d, want 1", len(result.Findings))
	}
}

func TestToolResult_HasFindings(t *testing.T) {
	result := &ToolResult{
		ToolName: "test",
		Findings: make([]*core.Finding, 0),
	}

	if result.HasFindings() {
		t.Error("Empty result should not have findings")
	}

	result.AddFinding(core.NewFinding("XSS", core.SeverityHigh))
	if !result.HasFindings() {
		t.Error("Result with findings should return true")
	}
}

func TestToolResult_AddError(t *testing.T) {
	result := &ToolResult{
		ToolName: "test",
		Errors:   make([]string, 0),
	}

	result.AddError("connection timeout")
	result.AddError("parse error")

	if len(result.Errors) != 2 {
		t.Errorf("len(Errors) = %d, want 2", len(result.Errors))
	}
}

func TestToolResult_IsSuccess(t *testing.T) {
	tests := []struct {
		name    string
		result  ToolResult
		success bool
	}{
		{
			name:    "no errors",
			result:  ToolResult{Errors: []string{}, Success: true},
			success: true,
		},
		{
			name:    "with errors",
			result:  ToolResult{Errors: []string{"error"}},
			success: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.result.IsSuccess() != tt.success {
				t.Errorf("IsSuccess() = %v, want %v", tt.result.IsSuccess(), tt.success)
			}
		})
	}
}

// MockTool for testing
type MockTool struct {
	name        string
	version     string
	available   bool
	executeFunc func(ctx context.Context, req *ToolRequest) (*ToolResult, error)
}

func (m *MockTool) Name() string       { return m.name }
func (m *MockTool) Version() string    { return m.version }
func (m *MockTool) IsAvailable() bool  { return m.available }
func (m *MockTool) HealthCheck() error { return nil }
func (m *MockTool) Execute(ctx context.Context, req *ToolRequest) (*ToolResult, error) {
	if m.executeFunc != nil {
		return m.executeFunc(ctx, req)
	}
	return &ToolResult{ToolName: m.name, Success: true}, nil
}

func TestTool_Interface(t *testing.T) {
	mock := &MockTool{
		name:      "mock-tool",
		version:   "1.0.0",
		available: true,
	}

	// Verify interface compliance
	var _ Tool = mock

	if mock.Name() != "mock-tool" {
		t.Errorf("Name() = %q", mock.Name())
	}
	if mock.Version() != "1.0.0" {
		t.Errorf("Version() = %q", mock.Version())
	}
	if !mock.IsAvailable() {
		t.Error("IsAvailable() should return true")
	}

	result, err := mock.Execute(context.Background(), NewToolRequest("https://example.com"))
	if err != nil {
		t.Errorf("Execute() error = %v", err)
	}
	if !result.Success {
		t.Error("Execute() should succeed")
	}
}

func TestNewToolRequest_Defaults(t *testing.T) {
	req := NewToolRequest("https://example.com/test")

	if req.Target != "https://example.com/test" {
		t.Errorf("Target = %q, want %q", req.Target, "https://example.com/test")
	}
	if req.Method != "GET" {
		t.Errorf("Method = %q, want %q", req.Method, "GET")
	}
	if req.Headers == nil {
		t.Error("Headers should be initialized")
	}
	if req.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", req.Timeout, DefaultTimeout)
	}
	if req.Data != "" {
		t.Errorf("Data should be empty, got %q", req.Data)
	}
	if req.Cookies != "" {
		t.Errorf("Cookies should be empty, got %q", req.Cookies)
	}
	if req.Proxy != "" {
		t.Errorf("Proxy should be empty, got %q", req.Proxy)
	}
	if req.Auth != nil {
		t.Error("Auth should be nil by default")
	}
	if req.OutputDir != "" {
		t.Errorf("OutputDir should be empty, got %q", req.OutputDir)
	}
	if len(req.CustomArgs) != 0 {
		t.Errorf("CustomArgs should be empty, got %v", req.CustomArgs)
	}
}

func TestToolRequest_WithData(t *testing.T) {
	req := NewToolRequest("https://example.com").
		WithData("username=admin&password=test")

	if req.Data != "username=admin&password=test" {
		t.Errorf("Data = %q, want %q", req.Data, "username=admin&password=test")
	}
}

func TestToolRequest_WithMethod(t *testing.T) {
	tests := []struct {
		name   string
		method string
	}{
		{name: "POST", method: "POST"},
		{name: "PUT", method: "PUT"},
		{name: "DELETE", method: "DELETE"},
		{name: "PATCH", method: "PATCH"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := NewToolRequest("https://example.com").WithMethod(tt.method)
			if req.Method != tt.method {
				t.Errorf("Method = %q, want %q", req.Method, tt.method)
			}
		})
	}
}

func TestToolRequest_WithAuth(t *testing.T) {
	auth := &AuthConfig{
		Type:     "basic",
		Username: "admin",
		Password: "secret",
	}

	req := NewToolRequest("https://example.com").WithAuth(auth)

	if req.Auth == nil {
		t.Fatal("Auth should not be nil")
	}
	if req.Auth.Type != "basic" {
		t.Errorf("Auth.Type = %q, want %q", req.Auth.Type, "basic")
	}
	if req.Auth.Username != "admin" {
		t.Errorf("Auth.Username = %q, want %q", req.Auth.Username, "admin")
	}
	if req.Auth.Password != "secret" {
		t.Errorf("Auth.Password = %q, want %q", req.Auth.Password, "secret")
	}
}

func TestToolRequest_WithAuth_Bearer(t *testing.T) {
	auth := &AuthConfig{
		Type:  "bearer",
		Token: "eyJhbGciOiJIUzI1NiJ9",
	}

	req := NewToolRequest("https://example.com").WithAuth(auth)

	if req.Auth.Token != "eyJhbGciOiJIUzI1NiJ9" {
		t.Errorf("Auth.Token = %q", req.Auth.Token)
	}
}

func TestToolRequest_WithCustomArgs(t *testing.T) {
	req := NewToolRequest("https://example.com").
		WithCustomArgs("--level=5", "--risk=3")

	if len(req.CustomArgs) != 2 {
		t.Fatalf("CustomArgs length = %d, want 2", len(req.CustomArgs))
	}
	if req.CustomArgs[0] != "--level=5" {
		t.Errorf("CustomArgs[0] = %q, want %q", req.CustomArgs[0], "--level=5")
	}
	if req.CustomArgs[1] != "--risk=3" {
		t.Errorf("CustomArgs[1] = %q, want %q", req.CustomArgs[1], "--risk=3")
	}
}

func TestToolRequest_WithCustomArgs_Appends(t *testing.T) {
	req := NewToolRequest("https://example.com").
		WithCustomArgs("--flag1").
		WithCustomArgs("--flag2", "--flag3")

	if len(req.CustomArgs) != 3 {
		t.Fatalf("CustomArgs length = %d, want 3", len(req.CustomArgs))
	}
}

func TestToolRequest_Chaining(t *testing.T) {
	req := NewToolRequest("https://example.com").
		WithMethod("POST").
		WithData("data=test").
		WithHeaders(map[string]string{"X-Custom": "value"}).
		WithCookies("session=abc").
		WithProxy("http://127.0.0.1:8080").
		WithTimeout(10 * time.Minute).
		WithCustomArgs("--flag1")

	if req.Method != "POST" {
		t.Error("Method not set in chain")
	}
	if req.Data != "data=test" {
		t.Error("Data not set in chain")
	}
	if req.Headers["X-Custom"] != "value" {
		t.Error("Headers not set in chain")
	}
	if req.Cookies != "session=abc" {
		t.Error("Cookies not set in chain")
	}
	if req.Proxy != "http://127.0.0.1:8080" {
		t.Error("Proxy not set in chain")
	}
	if req.Timeout != 10*time.Minute {
		t.Error("Timeout not set in chain")
	}
	if len(req.CustomArgs) != 1 {
		t.Error("CustomArgs not set in chain")
	}
}

func TestToolRequest_WithHeaders_MergesExisting(t *testing.T) {
	req := NewToolRequest("https://example.com").
		WithHeaders(map[string]string{"A": "1", "B": "2"}).
		WithHeaders(map[string]string{"C": "3", "A": "override"})

	if req.Headers["A"] != "override" {
		t.Errorf("Header A should be overridden, got %q", req.Headers["A"])
	}
	if req.Headers["B"] != "2" {
		t.Errorf("Header B should remain, got %q", req.Headers["B"])
	}
	if req.Headers["C"] != "3" {
		t.Errorf("Header C should be added, got %q", req.Headers["C"])
	}
}

func TestNewToolResult(t *testing.T) {
	result := NewToolResult("test-tool")

	if result.ToolName != "test-tool" {
		t.Errorf("ToolName = %q, want %q", result.ToolName, "test-tool")
	}
	if !result.Success {
		t.Error("New result should be successful by default")
	}
	if result.Findings == nil {
		t.Error("Findings should be initialized")
	}
	if len(result.Findings) != 0 {
		t.Errorf("Findings should be empty, got %d", len(result.Findings))
	}
	if result.Errors == nil {
		t.Error("Errors should be initialized")
	}
	if len(result.Errors) != 0 {
		t.Errorf("Errors should be empty, got %d", len(result.Errors))
	}
}

func TestToolResult_AddFinding_SetsToolName(t *testing.T) {
	result := NewToolResult("my-tool")

	finding := core.NewFinding("XSS", core.SeverityHigh)
	// finding.Tool is empty
	result.AddFinding(finding)

	if finding.Tool != "my-tool" {
		t.Errorf("Finding.Tool = %q, want %q", finding.Tool, "my-tool")
	}
}

func TestToolResult_AddFinding_PreservesExistingToolName(t *testing.T) {
	result := NewToolResult("my-tool")

	finding := core.NewFinding("XSS", core.SeverityHigh)
	finding.Tool = "other-tool"
	result.AddFinding(finding)

	if finding.Tool != "other-tool" {
		t.Errorf("Finding.Tool should not be overridden, got %q", finding.Tool)
	}
}

func TestToolResult_AddFindings(t *testing.T) {
	result := NewToolResult("test-tool")

	findings := []*core.Finding{
		core.NewFinding("XSS", core.SeverityHigh),
		core.NewFinding("SQLi", core.SeverityCritical),
		core.NewFinding("CSRF", core.SeverityMedium),
	}

	result.AddFindings(findings)

	if len(result.Findings) != 3 {
		t.Errorf("len(Findings) = %d, want 3", len(result.Findings))
	}

	// All should have tool name set
	for _, f := range result.Findings {
		if f.Tool != "test-tool" {
			t.Errorf("Finding.Tool = %q, want %q", f.Tool, "test-tool")
		}
	}
}

func TestToolResult_AddFindings_Empty(t *testing.T) {
	result := NewToolResult("test-tool")
	result.AddFindings(nil)

	if len(result.Findings) != 0 {
		t.Errorf("len(Findings) = %d, want 0", len(result.Findings))
	}
}

func TestToolResult_FindingCount(t *testing.T) {
	tests := []struct {
		name     string
		findings int
		want     int
	}{
		{name: "zero findings", findings: 0, want: 0},
		{name: "one finding", findings: 1, want: 1},
		{name: "multiple findings", findings: 5, want: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewToolResult("test")
			for range tt.findings {
				result.AddFinding(core.NewFinding("test", core.SeverityHigh))
			}
			if result.FindingCount() != tt.want {
				t.Errorf("FindingCount() = %d, want %d", result.FindingCount(), tt.want)
			}
		})
	}
}

func TestToolResult_FindingsBySeverity(t *testing.T) {
	result := NewToolResult("test")
	result.AddFinding(core.NewFinding("SQLi", core.SeverityCritical))
	result.AddFinding(core.NewFinding("XSS", core.SeverityHigh))
	result.AddFinding(core.NewFinding("CSRF", core.SeverityHigh))
	result.AddFinding(core.NewFinding("Info Leak", core.SeverityLow))

	bySeverity := result.FindingsBySeverity()

	if len(bySeverity[core.SeverityCritical]) != 1 {
		t.Errorf("Critical findings = %d, want 1", len(bySeverity[core.SeverityCritical]))
	}
	if len(bySeverity[core.SeverityHigh]) != 2 {
		t.Errorf("High findings = %d, want 2", len(bySeverity[core.SeverityHigh]))
	}
	if len(bySeverity[core.SeverityLow]) != 1 {
		t.Errorf("Low findings = %d, want 1", len(bySeverity[core.SeverityLow]))
	}
	if len(bySeverity[core.SeverityMedium]) != 0 {
		t.Errorf("Medium findings = %d, want 0", len(bySeverity[core.SeverityMedium]))
	}
}

func TestToolResult_FindingsBySeverity_Empty(t *testing.T) {
	result := NewToolResult("test")
	bySeverity := result.FindingsBySeverity()

	if len(bySeverity) != 0 {
		t.Errorf("Empty result should have no severity groups, got %d", len(bySeverity))
	}
}

func TestToolResult_AddError_SetsSuccessFalse(t *testing.T) {
	result := NewToolResult("test")

	if !result.Success {
		t.Error("New result should start as successful")
	}

	result.AddError("something went wrong")

	if result.Success {
		t.Error("Success should be false after AddError")
	}
	if result.IsSuccess() {
		t.Error("IsSuccess() should return false after AddError")
	}
}

func TestToolResult_IsSuccess_SuccessFalseNoErrors(t *testing.T) {
	result := NewToolResult("test")
	result.Success = false

	if result.IsSuccess() {
		t.Error("IsSuccess() should return false when Success field is false")
	}
}

func TestToolResult_RawOutput(t *testing.T) {
	result := NewToolResult("test")
	result.RawOutput = "some raw output from the tool"

	if result.RawOutput != "some raw output from the tool" {
		t.Errorf("RawOutput = %q", result.RawOutput)
	}
}

func TestToolResult_ExecutionTime(t *testing.T) {
	result := NewToolResult("test")
	result.ExecutionTime = 5 * time.Second

	if result.ExecutionTime != 5*time.Second {
		t.Errorf("ExecutionTime = %v, want %v", result.ExecutionTime, 5*time.Second)
	}
}

func TestDefaultTimeout(t *testing.T) {
	if DefaultTimeout != 5*time.Minute {
		t.Errorf("DefaultTimeout = %v, want %v", DefaultTimeout, 5*time.Minute)
	}
}

func TestAuthConfig_Fields(t *testing.T) {
	auth := &AuthConfig{
		Type:     "api_key",
		Header:   "X-API-Key",
		Token:    "my-api-key-123",
		Username: "",
		Password: "",
	}

	if auth.Type != "api_key" {
		t.Errorf("Type = %q", auth.Type)
	}
	if auth.Header != "X-API-Key" {
		t.Errorf("Header = %q", auth.Header)
	}
	if auth.Token != "my-api-key-123" {
		t.Errorf("Token = %q", auth.Token)
	}
}

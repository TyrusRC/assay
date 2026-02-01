package tools

import (
	"context"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
)

// DefaultTimeout is the default timeout for tool execution.
const DefaultTimeout = 5 * time.Minute

// Tool is the interface that all external security tools must implement.
type Tool interface {
	// Name returns the tool name.
	Name() string

	// Version returns the tool version.
	Version() string

	// IsAvailable checks if the tool binary is available on the system.
	IsAvailable() bool

	// HealthCheck verifies the tool is working correctly.
	HealthCheck() error

	// Execute runs the tool against the target.
	Execute(ctx context.Context, req *ToolRequest) (*ToolResult, error)
}

// ToolRequest represents a request to execute a tool.
type ToolRequest struct {
	// Target URL to scan
	Target string

	// HTTP Method (GET, POST, etc.)
	Method string

	// HTTP Headers to include
	Headers map[string]string

	// Cookies string
	Cookies string

	// Request body data
	Data string

	// Authentication configuration
	Auth *AuthConfig

	// Proxy URL (e.g., http://127.0.0.1:8080)
	Proxy string

	// Execution timeout
	Timeout time.Duration

	// Custom command-line arguments
	CustomArgs []string

	// Output directory for tool results
	OutputDir string
}

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	Type     string // basic, bearer, api_key
	Username string
	Password string
	Token    string
	Header   string
}

// NewToolRequest creates a new ToolRequest with defaults.
func NewToolRequest(target string) *ToolRequest {
	return &ToolRequest{
		Target:  target,
		Method:  "GET",
		Headers: make(map[string]string),
		Timeout: DefaultTimeout,
	}
}

// WithHeaders sets headers and returns the request for chaining.
func (r *ToolRequest) WithHeaders(headers map[string]string) *ToolRequest {
	for k, v := range headers {
		r.Headers[k] = v
	}
	return r
}

// WithCookies sets cookies and returns the request for chaining.
func (r *ToolRequest) WithCookies(cookies string) *ToolRequest {
	r.Cookies = cookies
	return r
}

// WithData sets the request body and returns the request for chaining.
func (r *ToolRequest) WithData(data string) *ToolRequest {
	r.Data = data
	return r
}

// WithMethod sets the HTTP method and returns the request for chaining.
func (r *ToolRequest) WithMethod(method string) *ToolRequest {
	r.Method = method
	return r
}

// WithTimeout sets the timeout and returns the request for chaining.
func (r *ToolRequest) WithTimeout(timeout time.Duration) *ToolRequest {
	r.Timeout = timeout
	return r
}

// WithProxy sets the proxy and returns the request for chaining.
func (r *ToolRequest) WithProxy(proxy string) *ToolRequest {
	r.Proxy = proxy
	return r
}

// WithAuth sets authentication and returns the request for chaining.
func (r *ToolRequest) WithAuth(auth *AuthConfig) *ToolRequest {
	r.Auth = auth
	return r
}

// WithCustomArgs adds custom arguments and returns the request for chaining.
func (r *ToolRequest) WithCustomArgs(args ...string) *ToolRequest {
	r.CustomArgs = append(r.CustomArgs, args...)
	return r
}

// ToolResult represents the result of a tool execution.
type ToolResult struct {
	// Tool name
	ToolName string

	// Execution success status
	Success bool

	// Discovered findings
	Findings []*core.Finding

	// Raw tool output
	RawOutput string

	// Execution duration
	ExecutionTime time.Duration

	// Errors encountered
	Errors []string
}

// NewToolResult creates a new ToolResult.
func NewToolResult(toolName string) *ToolResult {
	return &ToolResult{
		ToolName: toolName,
		Findings: make([]*core.Finding, 0),
		Errors:   make([]string, 0),
		Success:  true,
	}
}

// AddFinding adds a finding to the result.
func (r *ToolResult) AddFinding(finding *core.Finding) {
	if finding.Tool == "" {
		finding.Tool = r.ToolName
	}
	r.Findings = append(r.Findings, finding)
}

// AddFindings adds multiple findings to the result.
func (r *ToolResult) AddFindings(findings []*core.Finding) {
	for _, f := range findings {
		r.AddFinding(f)
	}
}

// HasFindings returns true if there are any findings.
func (r *ToolResult) HasFindings() bool {
	return len(r.Findings) > 0
}

// AddError adds an error message to the result.
func (r *ToolResult) AddError(err string) {
	r.Errors = append(r.Errors, err)
	r.Success = false
}

// IsSuccess returns true if execution was successful.
func (r *ToolResult) IsSuccess() bool {
	return r.Success && len(r.Errors) == 0
}

// FindingCount returns the number of findings.
func (r *ToolResult) FindingCount() int {
	return len(r.Findings)
}

// FindingsBySeverity returns findings grouped by severity.
func (r *ToolResult) FindingsBySeverity() map[core.Severity][]*core.Finding {
	result := make(map[core.Severity][]*core.Finding)
	for _, f := range r.Findings {
		result[f.Severity] = append(result[f.Severity], f)
	}
	return result
}

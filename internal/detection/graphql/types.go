package graphql

import (
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
)

// VulnerabilityType represents the type of GraphQL vulnerability.
type VulnerabilityType int

const (
	// VulnIntrospectionEnabled indicates introspection queries are allowed.
	VulnIntrospectionEnabled VulnerabilityType = iota
	// VulnBatchQueryAttack indicates batch queries are allowed without limits.
	VulnBatchQueryAttack
	// VulnDepthLimitBypass indicates deeply nested queries are allowed.
	VulnDepthLimitBypass
	// VulnFieldSuggestion indicates field suggestions expose schema information.
	VulnFieldSuggestion
	// VulnInjectionInArgs indicates SQL/NoSQL injection in GraphQL arguments.
	VulnInjectionInArgs
	// VulnAuthorizationBypass indicates authorization can be bypassed.
	VulnAuthorizationBypass
)

// String returns the string representation of the vulnerability type.
func (v VulnerabilityType) String() string {
	switch v {
	case VulnIntrospectionEnabled:
		return "introspection-enabled"
	case VulnBatchQueryAttack:
		return "batch-query-attack"
	case VulnDepthLimitBypass:
		return "depth-limit-bypass"
	case VulnFieldSuggestion:
		return "field-suggestion-disclosure"
	case VulnInjectionInArgs:
		return "injection-in-arguments"
	case VulnAuthorizationBypass:
		return "authorization-bypass"
	default:
		return "unknown"
	}
}

// InjectionType represents the type of injection attack.
type InjectionType string

const (
	// InjectionTypeSQL represents SQL injection.
	InjectionTypeSQL InjectionType = "sql"
	// InjectionTypeNoSQL represents NoSQL injection.
	InjectionTypeNoSQL InjectionType = "nosql"
)

// InjectionPayload represents an injection test payload.
type InjectionPayload struct {
	Value       string
	Type        InjectionType
	Description string
}

// DetectOptions configures GraphQL detection behavior.
type DetectOptions struct {
	// Timeout for each request
	Timeout time.Duration
	// Maximum query depth to test
	MaxDepth int
	// Maximum batch size to test
	MaxBatchSize int
	// Test for batch query vulnerabilities
	TestBatchQueries bool
	// Test for depth limit bypass
	TestDepthLimit bool
	// Test for field suggestion disclosure
	TestFieldSuggestion bool
	// Test for injection vulnerabilities
	TestInjection bool
	// Test for authorization bypass
	TestAuthorization bool
	// Custom authorization header
	AuthHeader string
	// Custom authorization value
	AuthValue string
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		Timeout:             30 * time.Second,
		MaxDepth:            15,
		MaxBatchSize:        10,
		TestBatchQueries:    true,
		TestDepthLimit:      true,
		TestFieldSuggestion: true,
		TestInjection:       true,
		TestAuthorization:   false,
	}
}

// DetectionResult contains GraphQL vulnerability detection results.
type DetectionResult struct {
	IsGraphQL       bool
	Endpoint        string
	Findings        []*core.Finding
	IntrospectionOK bool
	SchemaTypes     []string
}

// HasVulnerabilities returns true if any vulnerabilities were found.
func (r *DetectionResult) HasVulnerabilities() bool {
	return len(r.Findings) > 0
}

// IntrospectionResult contains introspection analysis results.
type IntrospectionResult struct {
	Enabled      bool
	Types        []string
	QueryType    string
	MutationType string
	RawResponse  string
}

// BatchResult contains batch query analysis results.
type BatchResult struct {
	Vulnerable    bool
	ResponseCount int
	Evidence      string
}

// DepthResult contains depth limit analysis results.
type DepthResult struct {
	Vulnerable   bool
	MaxDepthTest int
	Evidence     string
}

// FieldSuggestionResult contains field suggestion analysis results.
type FieldSuggestionResult struct {
	HasSuggestions  bool
	SuggestedFields []string
	Evidence        string
}

// InjectionResult contains injection analysis results.
type InjectionResult struct {
	Vulnerable    bool
	InjectionType InjectionType
	Evidence      string
	DatabaseType  string
}

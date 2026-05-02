package graphql

import (
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
)

// CreateFinding creates a Finding from a GraphQL vulnerability.
func (d *Detector) CreateFinding(vulnType VulnerabilityType, url, description, evidence string) *core.Finding {
	var severity core.Severity
	var findingType string
	var apiTop10 []string
	var cwe []string
	var remediation string

	switch vulnType {
	case VulnIntrospectionEnabled:
		severity = core.SeverityMedium
		findingType = "GraphQL Introspection Enabled"
		apiTop10 = []string{"API3:2023 - Broken Object Property Level Authorization"}
		cwe = []string{"CWE-200"}
		remediation = "Disable introspection in production environments. " +
			"Use allowlists for permitted queries. " +
			"Implement proper access controls on schema visibility."

	case VulnBatchQueryAttack:
		severity = core.SeverityMedium
		findingType = "GraphQL Batch Query Attack"
		apiTop10 = []string{"API4:2023 - Unrestricted Resource Consumption"}
		cwe = []string{"CWE-770"}
		remediation = "Implement rate limiting per query. " +
			"Limit batch query size. " +
			"Use query cost analysis to prevent resource exhaustion."

	case VulnDepthLimitBypass:
		severity = core.SeverityMedium
		findingType = "GraphQL Depth Limit Bypass"
		apiTop10 = []string{"API4:2023 - Unrestricted Resource Consumption"}
		cwe = []string{"CWE-770", "CWE-400"}
		remediation = "Implement query depth limits. " +
			"Use query complexity analysis. " +
			"Set timeouts for query execution."

	case VulnFieldSuggestion:
		severity = core.SeverityLow
		findingType = "GraphQL Field Suggestion Disclosure"
		apiTop10 = []string{"API3:2023 - Broken Object Property Level Authorization"}
		cwe = []string{"CWE-200", "CWE-209"}
		remediation = "Disable field suggestions in production. " +
			"Use generic error messages. " +
			"Implement proper error handling."

	case VulnInjectionInArgs:
		severity = core.SeverityHigh
		findingType = "GraphQL Injection Vulnerability"
		apiTop10 = []string{"API8:2023 - Security Misconfiguration"}
		cwe = []string{"CWE-89", "CWE-943"}
		remediation = "Use parameterized queries. " +
			"Validate and sanitize all input. " +
			"Implement proper input type checking in GraphQL resolvers."

	case VulnAuthorizationBypass:
		severity = core.SeverityCritical
		findingType = "GraphQL Authorization Bypass"
		apiTop10 = []string{"API1:2023 - Broken Object Level Authorization"}
		cwe = []string{"CWE-862", "CWE-863"}
		remediation = "Implement proper authorization in all resolvers. " +
			"Use field-level authorization. " +
			"Validate user permissions before data access."

	default:
		severity = core.SeverityInfo
		findingType = "GraphQL Security Issue"
		apiTop10 = []string{"API10:2023 - Unsafe Consumption of APIs"}
		cwe = []string{"CWE-1059"}
		remediation = "Review GraphQL security configuration."
	}

	finding := core.NewFinding(findingType, severity)
	finding.URL = url
	finding.Description = description
	finding.Evidence = evidence
	finding.Tool = "graphql-detector"
	finding.Remediation = remediation
	finding.APITop10 = apiTop10
	finding.CWE = cwe

	// Add OWASP WSTG mapping
	finding.WSTG = []string{"WSTG-CONF-10", "WSTG-INPV-12"}

	return finding
}

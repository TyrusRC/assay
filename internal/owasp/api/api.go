// Package api provides OWASP API Security Top 10 mappings.
// It maps API vulnerability findings to the OWASP API Security Top 10 2023 categories.
package api

import "strings"

// Category represents an OWASP API Security Top 10 2023 category.
type Category struct {
	ID          string
	Name        string
	Description string
	Impact      string
	Prevention  []string
	CWEs        []string
}

// GetCategory returns an API Security Top 10 category by ID.
func GetCategory(id string) *Category {
	if cat, ok := categories[id]; ok {
		return &cat
	}
	return nil
}

// GetAllCategories returns all API Security Top 10 categories.
func GetAllCategories() map[string]Category {
	result := make(map[string]Category, len(categories))
	for k, v := range categories {
		result[k] = v
	}
	return result
}

// VulnerabilityMapping maps API vulnerability types to API Top 10 categories.
var VulnerabilityMapping = map[string]string{
	// API1:2023 - Broken Object Level Authorization
	"BOLA":                              "API1:2023",
	"Broken Object Level Authorization": "API1:2023",
	"IDOR":                              "API1:2023",
	"Insecure Direct Object Reference":  "API1:2023",
	"Object Level Authorization":        "API1:2023",

	// API2:2023 - Broken Authentication
	"Broken Authentication":     "API2:2023",
	"API Authentication Bypass": "API2:2023",
	"Weak API Key":              "API2:2023",
	"Missing Authentication":    "API2:2023",
	"JWT Vulnerability":         "API2:2023",

	// API3:2023 - Broken Object Property Level Authorization
	"BOPLA": "API3:2023",
	"Broken Object Property Level Authorization": "API3:2023",
	"Mass Assignment":         "API3:2023",
	"Excessive Data Exposure": "API3:2023",

	// API4:2023 - Unrestricted Resource Consumption
	"Unrestricted Resource Consumption": "API4:2023",
	"Rate Limiting Missing":             "API4:2023",
	"API DoS":                           "API4:2023",
	"Resource Exhaustion":               "API4:2023",
	"Missing Rate Limit":                "API4:2023",

	// API5:2023 - Broken Function Level Authorization
	"BFLA":                                "API5:2023",
	"Broken Function Level Authorization": "API5:2023",
	"Privilege Escalation":                "API5:2023",
	"Admin Function Exposure":             "API5:2023",

	// API6:2023 - Unrestricted Access to Sensitive Business Flows
	"Unrestricted Business Flow Access": "API6:2023",
	"Business Logic Abuse":              "API6:2023",
	"Automated Threat":                  "API6:2023",

	// API7:2023 - Server Side Request Forgery
	"SSRF":                        "API7:2023",
	"Server-Side Request Forgery": "API7:2023",
	"API SSRF":                    "API7:2023",

	// API8:2023 - Security Misconfiguration
	"API Security Misconfiguration": "API8:2023",
	"CORS Misconfiguration":         "API8:2023",
	"Verbose Error Messages":        "API8:2023",
	"Missing Security Headers":      "API8:2023",
	"Open API Endpoint":             "API8:2023",

	// API9:2023 - Improper Inventory Management
	"Improper Inventory Management": "API9:2023",
	"Shadow API":                    "API9:2023",
	"Deprecated API":                "API9:2023",
	"Undocumented Endpoint":         "API9:2023",

	// API10:2023 - Unsafe Consumption of APIs
	"Unsafe API Consumption":   "API10:2023",
	"Third-party API Abuse":    "API10:2023",
	"Insecure API Integration": "API10:2023",
}

// GetAPITop10ForVulnerability returns the API Top 10 category ID for a vulnerability type.
func GetAPITop10ForVulnerability(vulnType string) string {
	if id, ok := VulnerabilityMapping[vulnType]; ok {
		return id
	}
	return ""
}

// OWASP API Security Top 10 2023 Categories
var categories = map[string]Category{
	"API1:2023": {
		ID:          "API1:2023",
		Name:        "Broken Object Level Authorization",
		Description: "APIs tend to expose endpoints that handle object identifiers, creating a wide attack surface of Object Level Access Control issues. Object level authorization checks should be considered in every function that accesses a data source using an ID from the user.",
		Impact:      "Unauthorized access to other users' objects can result in data disclosure to unauthorized parties, data loss, or data manipulation.",
		Prevention: []string{
			"Implement a proper authorization mechanism that relies on user policies and hierarchy",
			"Use the authorization mechanism to check if the logged-in user has access to perform the requested action on the record",
			"Use random and unpredictable values as GUIDs for records' IDs",
			"Write tests to evaluate the vulnerability of the authorization mechanism",
		},
		CWEs: []string{"CWE-284", "CWE-285", "CWE-639"},
	},
	"API2:2023": {
		ID:          "API2:2023",
		Name:        "Broken Authentication",
		Description: "Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens or to exploit implementation flaws to assume other user's identities temporarily or permanently.",
		Impact:      "Attackers can gain control of other users' accounts in the system, read their personal data, and perform sensitive actions on their behalf.",
		Prevention: []string{
			"Make sure you know all the possible flows to authenticate to the API",
			"Use standard authentication, token generation, password storage, and multi-factor authentication (MFA)",
			"Use short-lived access tokens",
			"Authenticate your apps (so you know who is talking to you)",
			"Use stricter rate-limiting for authentication",
		},
		CWEs: []string{"CWE-287", "CWE-306", "CWE-798"},
	},
	"API3:2023": {
		ID:          "API3:2023",
		Name:        "Broken Object Property Level Authorization",
		Description: "This category combines the former Excessive Data Exposure and Mass Assignment, focusing on the root cause: the lack of or improper authorization validation at the object property level.",
		Impact:      "Unauthorized access to private/sensitive object properties. Data can be manipulated by modifying object properties that should not be accessible.",
		Prevention: []string{
			"When exposing an object, make sure that the user should have access to all the object's properties you expose",
			"Avoid using generic methods such as to_json() and to_string()",
			"Cherry-pick specific object properties you specifically want to return",
			"Implement a schema-based response validation mechanism",
			"Keep returned data structures to the minimum required",
		},
		CWEs: []string{"CWE-213", "CWE-915"},
	},
	"API4:2023": {
		ID:          "API4:2023",
		Name:        "Unrestricted Resource Consumption",
		Description: "Satisfying API requests requires resources such as network bandwidth, CPU, memory, and storage. Sometimes required resources are made available by service providers via API integrations, and paid for per request. Attacks against APIs may consume more than intended resources.",
		Impact:      "Denial of Service (DoS), operational costs increase, or service degradation.",
		Prevention: []string{
			"Use a solution that makes it easy to limit memory, CPU, number of restarts, file descriptors, and processes",
			"Define and enforce a maximum size of data on all incoming parameters and payloads",
			"Implement rate limiting based on business needs",
			"Limit the number of records per response to prevent resource exhaustion",
			"Add proper server-side validation for query string and request body parameters",
		},
		CWEs: []string{"CWE-770", "CWE-400", "CWE-799"},
	},
	"API5:2023": {
		ID:          "API5:2023",
		Name:        "Broken Function Level Authorization",
		Description: "Complex access control policies with different hierarchies, groups, and roles, and an unclear separation between administrative and regular functions, tend to lead to authorization flaws. Attackers can access administrative functions that are exposed to regular users.",
		Impact:      "Attackers can access other users' resources and/or administrative functions.",
		Prevention: []string{
			"Make sure all of your administrative controllers inherit from an administrative abstract controller",
			"The enforcement mechanism(s) should deny all access by default",
			"Implement authorization checks in a centralized manner",
			"Review your API endpoints against function level authorization flaws",
		},
		CWEs: []string{"CWE-285", "CWE-269"},
	},
	"API6:2023": {
		ID:          "API6:2023",
		Name:        "Unrestricted Access to Sensitive Business Flows",
		Description: "APIs vulnerable to this risk expose a business flow - such as buying a ticket or posting a comment - without compensating for how the functionality could harm the business if used excessively in an automated manner.",
		Impact:      "This can harm the business in different ways: prevent legitimate users from purchasing a product, lead to inflation, or cause reputation damage.",
		Prevention: []string{
			"Identify the business flows that might harm the business if used excessively",
			"Choose the right protection mechanisms to mitigate the business risk",
			"Consider device fingerprinting, human detection mechanisms, and usage patterns",
			"Implement captcha or other human verification for sensitive operations",
		},
		CWEs: []string{"CWE-799", "CWE-770"},
	},
	"API7:2023": {
		ID:          "API7:2023",
		Name:        "Server Side Request Forgery",
		Description: "Server-Side Request Forgery (SSRF) flaws can occur when an API is fetching a remote resource without validating the user-supplied URL. This enables an attacker to coerce the application to send a crafted request to an unexpected destination.",
		Impact:      "SSRF can lead to internal services enumeration, information disclosure, bypassing firewalls, or other security measures.",
		Prevention: []string{
			"Isolate the resource fetching mechanism in your network",
			"Use allowlists for remote origins, URL schemes, ports, and accepted media types",
			"Disable HTTP redirections",
			"Use a well-tested URL parser to avoid issues caused by URL parsing inconsistencies",
			"Do not send raw responses to clients",
		},
		CWEs: []string{"CWE-918"},
	},
	"API8:2023": {
		ID:          "API8:2023",
		Name:        "Security Misconfiguration",
		Description: "APIs and the systems supporting them typically contain complex configurations meant to make the APIs more customizable. Security misconfiguration can occur at any level of the API stack, from the network level to the application level.",
		Impact:      "Misconfiguration can expose sensitive user data or system details, or lead to full server compromise.",
		Prevention: []string{
			"Implement a repeatable hardening process",
			"Ensure the entire API stack is properly configured",
			"Automate security configuration auditing",
			"Review and update configurations as part of the SDLC",
			"Implement proper CORS policies",
		},
		CWEs: []string{"CWE-2", "CWE-16", "CWE-388"},
	},
	"API9:2023": {
		ID:          "API9:2023",
		Name:        "Improper Inventory Management",
		Description: "APIs tend to expose more endpoints than traditional web applications, making proper and updated documentation highly important. A proper inventory of hosts and deployed API versions also are important to mitigate issues such as deprecated API versions and exposed debug endpoints.",
		Impact:      "Attackers may find non-production versions of the API (e.g., staging, beta) that are not as well protected and use those to mount attacks.",
		Prevention: []string{
			"Inventory all API hosts and document important aspects of each one",
			"Inventory integrated services and document important aspects",
			"Document all aspects of your API such as authentication, errors, redirects, rate limiting",
			"Automatically generate documentation using open standards",
			"Avoid using production data with non-production API deployments",
		},
		CWEs: []string{"CWE-1059"},
	},
	"API10:2023": {
		ID:          "API10:2023",
		Name:        "Unsafe Consumption of APIs",
		Description: "Developers tend to trust data received from third-party APIs more than user input, and so tend to adopt weaker security standards. In order to compromise APIs, attackers go after integrated third-party services instead of trying to compromise the target API directly.",
		Impact:      "Data theft, unauthorized access, or different kinds of injection attacks against the backend.",
		Prevention: []string{
			"When evaluating service providers, assess their API security posture",
			"Ensure all API interactions happen over a secure communication channel (TLS)",
			"Always validate and properly sanitize data received from integrated APIs",
			"Maintain an allowlist of well-known locations integrated APIs may redirect yours to",
			"Do not blindly follow redirects",
		},
		CWEs: []string{"CWE-20", "CWE-200", "CWE-319"},
	},
}

// APIEndpointRisk represents a risk assessment for an API endpoint.
type APIEndpointRisk struct {
	Endpoint    string
	Method      string
	Risks       []string // List of API Top 10 IDs
	Severity    string
	Description string
}

// AssessEndpointRisks analyzes an endpoint for potential API risks.
func AssessEndpointRisks(endpoint, method string, hasAuth, hasRateLimit, exposesData bool) []string {
	var risks []string

	// Check for common API vulnerabilities based on characteristics
	if !hasAuth {
		risks = append(risks, "API2:2023") // Broken Authentication
	}

	if !hasRateLimit {
		risks = append(risks, "API4:2023") // Unrestricted Resource Consumption
	}

	if exposesData {
		risks = append(risks, "API3:2023") // Broken Object Property Level Authorization
	}

	// Check endpoint patterns for specific risks
	if containsResourceID(endpoint) {
		risks = append(risks, "API1:2023") // BOLA
	}

	if isAdminEndpoint(endpoint) {
		risks = append(risks, "API5:2023") // BFLA
	}

	return risks
}

func containsResourceID(endpoint string) bool {
	patterns := []string{
		"/users/", "/accounts/", "/orders/", "/items/",
		"/profiles/", "/documents/", "/files/",
	}
	for _, p := range patterns {
		if strings.Contains(endpoint, p) {
			return true
		}
	}
	return false
}

// isAdminEndpoint checks if endpoint is an administrative function.
func isAdminEndpoint(endpoint string) bool {
	adminPatterns := []string{
		"/admin", "/manage", "/config", "/settings",
		"/internal", "/debug", "/system",
	}
	for _, p := range adminPatterns {
		if strings.Contains(endpoint, p) {
			return true
		}
	}
	return false
}

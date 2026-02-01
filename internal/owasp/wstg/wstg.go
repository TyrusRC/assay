// Package wstg provides OWASP Web Security Testing Guide mappings.
// It maps vulnerability findings to WSTG test cases for comprehensive coverage reporting.
package wstg

// Category represents a WSTG test category.
type Category string

const (
	CategoryInfoGathering Category = "INFO" // Information Gathering
	CategoryConfig        Category = "CONF" // Configuration and Deployment Management
	CategoryIdentity      Category = "IDNT" // Identity Management
	CategoryAuthn         Category = "ATHN" // Authentication
	CategoryAuthz         Category = "ATHZ" // Authorization
	CategorySession       Category = "SESS" // Session Management
	CategoryInputVal      Category = "INPV" // Input Validation
	CategoryErrorHandling Category = "ERRH" // Error Handling
	CategoryCrypto        Category = "CRYP" // Cryptography
	CategoryBusLogic      Category = "BUSL" // Business Logic
	CategoryClientSide    Category = "CLNT" // Client-side Testing
	CategoryAPI           Category = "APIT" // API Testing
)

// TestCase represents a WSTG test case.
type TestCase struct {
	ID          string
	Name        string
	Category    Category
	Description string
	Objective   string
	HowToTest   string
	Remediation string
	References  []string
}

// GetTestCase returns a test case by ID.
func GetTestCase(id string) *TestCase {
	if tc, ok := testCases[id]; ok {
		return &tc
	}
	return nil
}

// GetByCategory returns all test cases in a category.
func GetByCategory(category Category) []TestCase {
	var results []TestCase
	for _, tc := range testCases {
		if tc.Category == category {
			results = append(results, tc)
		}
	}
	return results
}

// GetAllTestCases returns all WSTG test cases.
func GetAllTestCases() map[string]TestCase {
	result := make(map[string]TestCase, len(testCases))
	for k, v := range testCases {
		result[k] = v
	}
	return result
}

// VulnerabilityMapping maps vulnerability types to WSTG test cases.
var VulnerabilityMapping = map[string][]string{
	"SQL Injection":                    {"WSTG-INPV-05"},
	"Cross-Site Scripting":             {"WSTG-INPV-01", "WSTG-INPV-02"},
	"XSS":                              {"WSTG-INPV-01", "WSTG-INPV-02"},
	"Command Injection":                {"WSTG-INPV-12"},
	"SSRF":                             {"WSTG-INPV-19"},
	"Server-Side Request Forgery":      {"WSTG-INPV-19"},
	"LFI":                              {"WSTG-INPV-11"},
	"Local File Inclusion":             {"WSTG-INPV-11"},
	"Path Traversal":                   {"WSTG-INPV-11"},
	"XXE":                              {"WSTG-INPV-07"},
	"XML External Entity":              {"WSTG-INPV-07"},
	"LDAP Injection":                   {"WSTG-INPV-06"},
	"XPath Injection":                  {"WSTG-INPV-09"},
	"SSTI":                             {"WSTG-INPV-18"},
	"Server-Side Template Injection":   {"WSTG-INPV-18"},
	"HTTP Header Injection":            {"WSTG-INPV-15"},
	"Open Redirect":                    {"WSTG-CLNT-04"},
	"CSRF":                             {"WSTG-SESS-05"},
	"Cross-Site Request Forgery":       {"WSTG-SESS-05"},
	"Session Fixation":                 {"WSTG-SESS-03"},
	"Weak Authentication":              {"WSTG-ATHN-01", "WSTG-ATHN-02"},
	"Broken Access Control":            {"WSTG-ATHZ-01", "WSTG-ATHZ-02"},
	"IDOR":                             {"WSTG-ATHZ-04"},
	"Insecure Direct Object Reference": {"WSTG-ATHZ-04"},
	"Information Disclosure":           {"WSTG-INFO-02", "WSTG-ERRH-01"},
	"Sensitive Data Exposure":          {"WSTG-CRYP-01"},
	"Weak Cryptography":                {"WSTG-CRYP-01", "WSTG-CRYP-04"},
}

// GetWSTGForVulnerability returns WSTG test case IDs for a vulnerability type.
func GetWSTGForVulnerability(vulnType string) []string {
	if ids, ok := VulnerabilityMapping[vulnType]; ok {
		return ids
	}
	return nil
}

// WSTG v4.2 test cases
var testCases = map[string]TestCase{
	// Input Validation Testing
	"WSTG-INPV-01": {
		ID:          "WSTG-INPV-01",
		Name:        "Testing for Reflected Cross Site Scripting",
		Category:    CategoryInputVal,
		Description: "Reflected XSS occurs when user input is immediately returned by a web application in an error message, search result, or any other response.",
		Objective:   "Identify variables that are reflected in responses and assess the input they accept and encoding applied on return.",
		Remediation: "Validate and sanitize all user input. Use context-aware output encoding. Implement Content Security Policy.",
	},
	"WSTG-INPV-02": {
		ID:          "WSTG-INPV-02",
		Name:        "Testing for Stored Cross Site Scripting",
		Category:    CategoryInputVal,
		Description: "Stored XSS occurs when user input is stored on the target server and later displayed to users.",
		Objective:   "Identify stored input that is reflected on the client-side and assess the input handling.",
		Remediation: "Validate and sanitize all user input before storage. Use output encoding when displaying stored data.",
	},
	"WSTG-INPV-05": {
		ID:          "WSTG-INPV-05",
		Name:        "Testing for SQL Injection",
		Category:    CategoryInputVal,
		Description: "SQL injection testing checks if it is possible to inject data into the application so that it executes a user-controlled SQL query.",
		Objective:   "Identify SQL injection points and assess the severity of the vulnerability.",
		Remediation: "Use parameterized queries or prepared statements. Implement input validation. Use ORM frameworks.",
	},
	"WSTG-INPV-06": {
		ID:          "WSTG-INPV-06",
		Name:        "Testing for LDAP Injection",
		Category:    CategoryInputVal,
		Description: "LDAP injection is an attack used to exploit web applications that construct LDAP statements from user input.",
		Objective:   "Identify LDAP injection points in the application.",
		Remediation: "Validate and escape all user input used in LDAP queries.",
	},
	"WSTG-INPV-07": {
		ID:          "WSTG-INPV-07",
		Name:        "Testing for XML Injection",
		Category:    CategoryInputVal,
		Description: "XML injection testing checks if it is possible to inject XML metacharacters to alter the application logic.",
		Objective:   "Identify XML injection points including XXE vulnerabilities.",
		Remediation: "Disable external entity processing. Validate XML input. Use less complex data formats when possible.",
	},
	"WSTG-INPV-09": {
		ID:          "WSTG-INPV-09",
		Name:        "Testing for XPath Injection",
		Category:    CategoryInputVal,
		Description: "XPath injection is an attack technique used to exploit applications that construct XPath queries from user input.",
		Objective:   "Identify XPath injection points in the application.",
		Remediation: "Use parameterized XPath queries. Validate and sanitize user input.",
	},
	"WSTG-INPV-11": {
		ID:          "WSTG-INPV-11",
		Name:        "Testing for Local File Inclusion",
		Category:    CategoryInputVal,
		Description: "LFI testing checks if the application allows access to files outside the intended scope through path manipulation.",
		Objective:   "Identify file inclusion vulnerabilities and assess what files can be accessed.",
		Remediation: "Use allowlists for file access. Validate and sanitize file paths. Disable unnecessary PHP wrappers.",
	},
	"WSTG-INPV-12": {
		ID:          "WSTG-INPV-12",
		Name:        "Testing for Command Injection",
		Category:    CategoryInputVal,
		Description: "Command injection tests whether an application passes unsafe user data to system commands.",
		Objective:   "Identify command injection points and assess the impact.",
		Remediation: "Avoid using system commands with user input. Use language-specific APIs instead of shell commands.",
	},
	"WSTG-INPV-15": {
		ID:          "WSTG-INPV-15",
		Name:        "Testing for HTTP Splitting/Smuggling",
		Category:    CategoryInputVal,
		Description: "HTTP splitting involves inserting malicious data in HTTP responses to inject headers or split responses.",
		Objective:   "Assess whether the application is vulnerable to HTTP header injection.",
		Remediation: "Validate and sanitize all user input used in HTTP headers.",
	},
	"WSTG-INPV-18": {
		ID:          "WSTG-INPV-18",
		Name:        "Testing for Server-side Template Injection",
		Category:    CategoryInputVal,
		Description: "SSTI occurs when user input is embedded in a template in an unsafe manner.",
		Objective:   "Identify template injection vulnerabilities and assess the template engine.",
		Remediation: "Never allow user input in templates. Use sandbox mode for template engines.",
	},
	"WSTG-INPV-19": {
		ID:          "WSTG-INPV-19",
		Name:        "Testing for Server-Side Request Forgery",
		Category:    CategoryInputVal,
		Description: "SSRF tests whether an attacker can make the server perform requests to unintended locations.",
		Objective:   "Identify SSRF vulnerabilities and assess what internal resources can be accessed.",
		Remediation: "Validate and whitelist URLs. Block requests to internal IP ranges. Disable unnecessary URL schemes.",
	},

	// Session Management Testing
	"WSTG-SESS-03": {
		ID:          "WSTG-SESS-03",
		Name:        "Testing for Session Fixation",
		Category:    CategorySession,
		Description: "Session fixation allows an attacker to hijack a valid user session by fixing the session ID.",
		Objective:   "Analyze the session renewal mechanism and test for session fixation.",
		Remediation: "Regenerate session ID after authentication. Invalidate old session tokens.",
	},
	"WSTG-SESS-05": {
		ID:          "WSTG-SESS-05",
		Name:        "Testing for Cross Site Request Forgery",
		Category:    CategorySession,
		Description: "CSRF forces an authenticated user to perform unwanted actions on a web application.",
		Objective:   "Determine if it's possible to initiate requests on behalf of a user.",
		Remediation: "Implement anti-CSRF tokens. Use SameSite cookie attribute. Verify Origin/Referer headers.",
	},

	// Authorization Testing
	"WSTG-ATHZ-01": {
		ID:          "WSTG-ATHZ-01",
		Name:        "Testing Directory Traversal File Include",
		Category:    CategoryAuthz,
		Description: "Tests for unauthorized access to files through path traversal.",
		Objective:   "Identify path traversal vulnerabilities in file access.",
		Remediation: "Use allowlists. Validate file paths. Implement proper access controls.",
	},
	"WSTG-ATHZ-02": {
		ID:          "WSTG-ATHZ-02",
		Name:        "Testing for Bypassing Authorization Schema",
		Category:    CategoryAuthz,
		Description: "Tests whether authorization controls can be bypassed.",
		Objective:   "Assess the robustness of authorization mechanisms.",
		Remediation: "Implement proper access controls. Verify authorization on every request.",
	},
	"WSTG-ATHZ-04": {
		ID:          "WSTG-ATHZ-04",
		Name:        "Testing for Insecure Direct Object References",
		Category:    CategoryAuthz,
		Description: "IDOR occurs when an application uses user-supplied input to access objects directly.",
		Objective:   "Identify IDOR vulnerabilities and assess the impact.",
		Remediation: "Implement proper access controls. Use indirect references. Validate user authorization.",
	},

	// Authentication Testing
	"WSTG-ATHN-01": {
		ID:          "WSTG-ATHN-01",
		Name:        "Testing for Credentials Transported over an Encrypted Channel",
		Category:    CategoryAuthn,
		Description: "Tests whether credentials are transmitted securely.",
		Objective:   "Ensure credentials are only transmitted over encrypted channels.",
		Remediation: "Use HTTPS for all authentication. Implement HSTS.",
	},
	"WSTG-ATHN-02": {
		ID:          "WSTG-ATHN-02",
		Name:        "Testing for Default Credentials",
		Category:    CategoryAuthn,
		Description: "Tests for the presence of default or easily guessable credentials.",
		Objective:   "Identify default credentials that could allow unauthorized access.",
		Remediation: "Change all default credentials. Implement strong password policies.",
	},

	// Information Gathering
	"WSTG-INFO-02": {
		ID:          "WSTG-INFO-02",
		Name:        "Fingerprinting Web Server",
		Category:    CategoryInfoGathering,
		Description: "Identifies the web server type and version.",
		Objective:   "Determine the type and version of the running web server.",
		Remediation: "Remove or obfuscate server version headers. Keep software updated.",
	},

	// Error Handling
	"WSTG-ERRH-01": {
		ID:          "WSTG-ERRH-01",
		Name:        "Testing for Improper Error Handling",
		Category:    CategoryErrorHandling,
		Description: "Tests for verbose error messages that disclose sensitive information.",
		Objective:   "Identify information leakage through error messages.",
		Remediation: "Implement custom error pages. Log errors server-side. Never display stack traces.",
	},

	// Cryptography
	"WSTG-CRYP-01": {
		ID:          "WSTG-CRYP-01",
		Name:        "Testing for Weak Transport Layer Security",
		Category:    CategoryCrypto,
		Description: "Tests the strength of TLS configuration.",
		Objective:   "Identify weak TLS configurations and cipher suites.",
		Remediation: "Use TLS 1.2+. Disable weak ciphers. Implement perfect forward secrecy.",
	},
	"WSTG-CRYP-04": {
		ID:          "WSTG-CRYP-04",
		Name:        "Testing for Weak Encryption",
		Category:    CategoryCrypto,
		Description: "Tests for the use of weak encryption algorithms.",
		Objective:   "Identify weak cryptographic implementations.",
		Remediation: "Use strong, modern encryption algorithms. Avoid deprecated algorithms.",
	},

	// Client-side Testing
	"WSTG-CLNT-04": {
		ID:          "WSTG-CLNT-04",
		Name:        "Testing for Client-side URL Redirect",
		Category:    CategoryClientSide,
		Description: "Tests for open redirect vulnerabilities.",
		Objective:   "Identify open redirect vulnerabilities.",
		Remediation: "Validate redirect URLs against allowlist. Use relative URLs.",
	},
}

// CoverageReport represents a WSTG coverage report.
type CoverageReport struct {
	TotalTests  int
	TestedCount int
	Findings    map[string]int // WSTG ID -> finding count
	Categories  map[Category]CategoryCoverage
}

// CategoryCoverage represents coverage for a single category.
type CategoryCoverage struct {
	Category    Category
	TotalTests  int
	TestedCount int
	Percentage  float64
}

// NewCoverageReport creates a new coverage report.
func NewCoverageReport() *CoverageReport {
	return &CoverageReport{
		TotalTests: len(testCases),
		Findings:   make(map[string]int),
		Categories: make(map[Category]CategoryCoverage),
	}
}

// AddFinding adds a finding to the coverage report.
func (r *CoverageReport) AddFinding(wstgID string) {
	r.Findings[wstgID]++
	if _, exists := r.Findings[wstgID]; exists && r.Findings[wstgID] == 1 {
		r.TestedCount++
	}
}

// CalculateCoverage calculates category coverage percentages.
func (r *CoverageReport) CalculateCoverage() {
	categoryTotals := make(map[Category]int)
	categoryTested := make(map[Category]int)

	for id, tc := range testCases {
		categoryTotals[tc.Category]++
		if r.Findings[id] > 0 {
			categoryTested[tc.Category]++
		}
	}

	for cat, total := range categoryTotals {
		tested := categoryTested[cat]
		r.Categories[cat] = CategoryCoverage{
			Category:    cat,
			TotalTests:  total,
			TestedCount: tested,
			Percentage:  float64(tested) / float64(total) * 100,
		}
	}
}

// Package top10 provides OWASP Top 10 vulnerability mappings.
// It maps vulnerability findings to the OWASP Top 10 2021 and 2025 categories.
// The 2025 version retains the same categories and ordering as 2021.
// VulnerabilityMapping points to 2025 IDs as the primary reference.
package top10

// Category represents an OWASP Top 10 category.
type Category struct {
	ID          string
	Version     string
	Name        string
	Description string
	CWEs        []string
	Remediation string
}

// Risk represents a Top 10 risk entry with additional metadata.
type Risk struct {
	Category
	Rank          int
	IncidenceRate string
	AvgCVSS       float64
	MaxCVSS       float64
	CommonCWEs    []CWE
}

// CWE represents a Common Weakness Enumeration entry.
type CWE struct {
	ID          string
	Name        string
	Description string
}

// GetCategory returns a Top 10 category by ID.
func GetCategory(id string) *Category {
	if cat, ok := categories[id]; ok {
		return &cat
	}
	return nil
}

// GetRisk returns a Risk entry by ID.
func GetRisk(id string) *Risk {
	if risk, ok := risks[id]; ok {
		return &risk
	}
	return nil
}

// GetAllCategories returns all Top 10 categories.
func GetAllCategories() map[string]Category {
	result := make(map[string]Category, len(categories))
	for k, v := range categories {
		result[k] = v
	}
	return result
}

// GetAllRisks returns all Top 10 risks with full metadata.
func GetAllRisks() map[string]Risk {
	return risks
}

// VulnerabilityMapping maps vulnerability types to Top 10 2025 categories.
var VulnerabilityMapping = map[string]string{
	// A01:2025 - Broken Access Control
	"Broken Access Control":            "A01:2025",
	"IDOR":                             "A01:2025",
	"Insecure Direct Object Reference": "A01:2025",
	"Path Traversal":                   "A01:2025",
	"LFI":                              "A01:2025",
	"Local File Inclusion":             "A01:2025",
	"Directory Traversal":              "A01:2025",
	"Privilege Escalation":             "A01:2025",
	"Missing Access Control":           "A01:2025",

	// A02:2025 - Cryptographic Failures
	"Cryptographic Failures":  "A02:2025",
	"Weak Encryption":         "A02:2025",
	"Sensitive Data Exposure": "A02:2025",
	"Missing Encryption":      "A02:2025",
	"Weak TLS":                "A02:2025",
	"Clear Text Transmission": "A02:2025",

	// A03:2025 - Injection
	"Injection":                      "A03:2025",
	"SQL Injection":                  "A03:2025",
	"XSS":                            "A03:2025",
	"Cross-Site Scripting":           "A03:2025",
	"Command Injection":              "A03:2025",
	"LDAP Injection":                 "A03:2025",
	"XPath Injection":                "A03:2025",
	"NoSQL Injection":                "A03:2025",
	"SSTI":                           "A03:2025",
	"Server-Side Template Injection": "A03:2025",
	"Header Injection":               "A03:2025",

	// A04:2025 - Insecure Design
	"Insecure Design":       "A04:2025",
	"Business Logic Flaw":   "A04:2025",
	"Missing Rate Limiting": "A04:2025",

	// A05:2025 - Security Misconfiguration
	"Security Misconfiguration": "A05:2025",
	"XXE":                       "A05:2025",
	"XML External Entity":       "A05:2025",
	"Default Credentials":       "A05:2025",
	"Verbose Error Messages":    "A05:2025",
	"Missing Security Headers":  "A05:2025",
	"Open Cloud Storage":        "A05:2025",

	// A06:2025 - Vulnerable Components
	"Vulnerable Components": "A06:2025",
	"Outdated Software":     "A06:2025",
	"Unpatched Software":    "A06:2025",
	"Known Vulnerability":   "A06:2025",

	// A07:2025 - Authentication Failures
	"Authentication Failures": "A07:2025",
	"Broken Authentication":   "A07:2025",
	"Weak Password":           "A07:2025",
	"Session Fixation":        "A07:2025",
	"Credential Stuffing":     "A07:2025",
	"Brute Force":             "A07:2025",

	// A08:2025 - Software and Data Integrity Failures
	"Software Integrity Failures": "A08:2025",
	"Insecure Deserialization":    "A08:2025",
	"CI/CD Pipeline Compromise":   "A08:2025",

	// A09:2025 - Security Logging and Monitoring Failures
	"Logging Failures":     "A09:2025",
	"Missing Audit Trail":  "A09:2025",
	"Insufficient Logging": "A09:2025",

	// A10:2025 - Server-Side Request Forgery
	"SSRF":                        "A10:2025",
	"Server-Side Request Forgery": "A10:2025",
}

// GetLatestCategory returns the 2025 version of a Top 10 category by base ID (e.g., "A03").
func GetLatestCategory(baseID string) *Category {
	latestID := baseID + ":2025"
	if cat, ok := categories[latestID]; ok {
		return &cat
	}
	return nil
}

// GetTop10ForVulnerability returns the Top 10 category ID for a vulnerability type.
func GetTop10ForVulnerability(vulnType string) string {
	if id, ok := VulnerabilityMapping[vulnType]; ok {
		return id
	}
	return ""
}

// OWASP Top 10 2021 and 2025 Categories
var categories = map[string]Category{
	"A01:2021": {
		ID:          "A01:2021",
		Version:     "2021",
		Name:        "Broken Access Control",
		Description: "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of data, or performing a business function outside the user's limits.",
		CWEs:        []string{"CWE-22", "CWE-23", "CWE-35", "CWE-59", "CWE-200", "CWE-201", "CWE-219", "CWE-264", "CWE-275", "CWE-276", "CWE-284", "CWE-285", "CWE-352", "CWE-359", "CWE-377", "CWE-402", "CWE-425", "CWE-441", "CWE-497", "CWE-538", "CWE-540", "CWE-548", "CWE-552", "CWE-566", "CWE-601", "CWE-639", "CWE-651", "CWE-668", "CWE-706", "CWE-862", "CWE-863", "CWE-913", "CWE-922", "CWE-1275"},
		Remediation: "Implement proper access control mechanisms. Deny by default. Enforce record ownership. Disable directory listing. Log access control failures. Rate limit API access.",
	},
	"A02:2021": {
		ID:          "A02:2021",
		Version:     "2021",
		Name:        "Cryptographic Failures",
		Description: "Failures related to cryptography which often leads to sensitive data exposure. This includes the need to ensure data protection in transit and at rest.",
		CWEs:        []string{"CWE-261", "CWE-296", "CWE-310", "CWE-319", "CWE-321", "CWE-322", "CWE-323", "CWE-324", "CWE-325", "CWE-326", "CWE-327", "CWE-328", "CWE-329", "CWE-330", "CWE-331", "CWE-335", "CWE-336", "CWE-337", "CWE-338", "CWE-339", "CWE-340", "CWE-347", "CWE-523", "CWE-720", "CWE-757", "CWE-759", "CWE-760", "CWE-780", "CWE-818", "CWE-916"},
		Remediation: "Classify data. Apply controls per classification. Don't store sensitive data unnecessarily. Encrypt all sensitive data at rest. Encrypt data in transit with TLS. Disable caching for sensitive data. Use strong algorithms and keys.",
	},
	"A03:2021": {
		ID:          "A03:2021",
		Version:     "2021",
		Name:        "Injection",
		Description: "An application is vulnerable to attack when user-supplied data is not validated, filtered, or sanitized by the application, or dynamic queries or non-parameterized calls without context-aware escaping are used directly in the interpreter.",
		CWEs:        []string{"CWE-20", "CWE-74", "CWE-75", "CWE-77", "CWE-78", "CWE-79", "CWE-80", "CWE-83", "CWE-87", "CWE-88", "CWE-89", "CWE-90", "CWE-91", "CWE-93", "CWE-94", "CWE-95", "CWE-96", "CWE-97", "CWE-98", "CWE-99", "CWE-100", "CWE-113", "CWE-116", "CWE-138", "CWE-184", "CWE-470", "CWE-471", "CWE-564", "CWE-610", "CWE-643", "CWE-644", "CWE-652", "CWE-917"},
		Remediation: "Use a safe API which avoids using the interpreter entirely. Use positive server-side input validation. Escape special characters. Use LIMIT in SQL to prevent mass disclosure.",
	},
	"A04:2021": {
		ID:          "A04:2021",
		Version:     "2021",
		Name:        "Insecure Design",
		Description: "Insecure design is a broad category representing different weaknesses, expressed as missing or ineffective control design. It is differentiated from implementation flaws.",
		CWEs:        []string{"CWE-73", "CWE-183", "CWE-209", "CWE-213", "CWE-235", "CWE-256", "CWE-257", "CWE-266", "CWE-269", "CWE-280", "CWE-311", "CWE-312", "CWE-313", "CWE-316", "CWE-419", "CWE-430", "CWE-434", "CWE-444", "CWE-451", "CWE-472", "CWE-501", "CWE-522", "CWE-525", "CWE-539", "CWE-579", "CWE-598", "CWE-602", "CWE-642", "CWE-646", "CWE-650", "CWE-653", "CWE-656", "CWE-657", "CWE-799", "CWE-807", "CWE-840", "CWE-841", "CWE-927", "CWE-1021", "CWE-1173"},
		Remediation: "Establish and use a secure development lifecycle. Use threat modeling for critical authentication, access control, business logic, and key flows. Integrate security language and controls into user stories. Write unit and integration tests.",
	},
	"A05:2021": {
		ID:          "A05:2021",
		Version:     "2021",
		Name:        "Security Misconfiguration",
		Description: "The application might be vulnerable if it is missing appropriate security hardening across any part of the application stack or has improperly configured permissions on cloud services.",
		CWEs:        []string{"CWE-2", "CWE-11", "CWE-13", "CWE-15", "CWE-16", "CWE-260", "CWE-315", "CWE-520", "CWE-526", "CWE-537", "CWE-541", "CWE-547", "CWE-611", "CWE-614", "CWE-756", "CWE-776", "CWE-942", "CWE-1004", "CWE-1032", "CWE-1174"},
		Remediation: "A repeatable hardening process. A minimal platform without unnecessary features. Review and update configurations. A segmented application architecture. Sending security directives to clients. An automated process to verify configurations.",
	},
	"A06:2021": {
		ID:          "A06:2021",
		Version:     "2021",
		Name:        "Vulnerable and Outdated Components",
		Description: "You are likely vulnerable if you do not know the versions of all components you use, if the software is vulnerable or unsupported, if you do not scan for vulnerabilities regularly, or do not fix or upgrade the underlying platform in a timely fashion.",
		CWEs:        []string{"CWE-1035", "CWE-1104"},
		Remediation: "Remove unused dependencies. Continuously inventory client-side and server-side components. Monitor for vulnerabilities. Only obtain components from official sources. Monitor for unmaintained libraries.",
	},
	"A07:2021": {
		ID:          "A07:2021",
		Version:     "2021",
		Name:        "Identification and Authentication Failures",
		Description: "Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks.",
		CWEs:        []string{"CWE-255", "CWE-259", "CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-295", "CWE-297", "CWE-300", "CWE-302", "CWE-304", "CWE-306", "CWE-307", "CWE-346", "CWE-384", "CWE-521", "CWE-613", "CWE-620", "CWE-640", "CWE-798", "CWE-940", "CWE-1216"},
		Remediation: "Implement multi-factor authentication. Do not deploy with default credentials. Implement weak password checks. Align password policies with NIST 800-63b. Harden against enumeration attacks. Limit failed login attempts. Use server-side session manager.",
	},
	"A08:2021": {
		ID:          "A08:2021",
		Version:     "2021",
		Name:        "Software and Data Integrity Failures",
		Description: "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. This includes insecure deserialization.",
		CWEs:        []string{"CWE-345", "CWE-353", "CWE-426", "CWE-494", "CWE-502", "CWE-565", "CWE-784", "CWE-829", "CWE-830", "CWE-913"},
		Remediation: "Use digital signatures. Verify software and data are from expected source. Ensure libraries are from trusted repositories. Use software composition analysis. Review code and config changes. Ensure CI/CD pipeline has proper segregation and access control.",
	},
	"A09:2021": {
		ID:          "A09:2021",
		Version:     "2021",
		Name:        "Security Logging and Monitoring Failures",
		Description: "This category helps detect, escalate, and respond to active breaches. Without logging and monitoring, breaches cannot be detected.",
		CWEs:        []string{"CWE-117", "CWE-223", "CWE-532", "CWE-778"},
		Remediation: "Ensure all login, access control, and server-side input validation failures are logged. Ensure logs are in a format for log management solutions. Ensure high-value transactions have audit trail. Establish effective monitoring and alerting. Establish incident response and recovery plan.",
	},
	"A10:2021": {
		ID:          "A10:2021",
		Version:     "2021",
		Name:        "Server-Side Request Forgery (SSRF)",
		Description: "SSRF flaws occur whenever a web application fetches a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination.",
		CWEs:        []string{"CWE-918"},
		Remediation: "Segment remote resource access. Enforce 'deny by default' firewall policies. Sanitize and validate all client-supplied input data. Do not send raw responses to clients. Disable HTTP redirections. Be aware of URL consistency to avoid DNS rebinding.",
	},

	// OWASP Top 10 2025 Categories
	"A01:2025": {
		ID:          "A01:2025",
		Version:     "2025",
		Name:        "Broken Access Control",
		Description: "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of data, or performing a business function outside the user's limits.",
		CWEs:        []string{"CWE-22", "CWE-23", "CWE-35", "CWE-59", "CWE-200", "CWE-201", "CWE-219", "CWE-264", "CWE-275", "CWE-276", "CWE-284", "CWE-285", "CWE-352", "CWE-359", "CWE-377", "CWE-402", "CWE-425", "CWE-441", "CWE-497", "CWE-538", "CWE-540", "CWE-548", "CWE-552", "CWE-566", "CWE-601", "CWE-639", "CWE-651", "CWE-668", "CWE-706", "CWE-862", "CWE-863", "CWE-913", "CWE-922", "CWE-1275"},
		Remediation: "Implement proper access control mechanisms. Deny by default. Enforce record ownership. Disable directory listing. Log access control failures. Rate limit API access.",
	},
	"A02:2025": {
		ID:          "A02:2025",
		Version:     "2025",
		Name:        "Cryptographic Failures",
		Description: "Failures related to cryptography which often leads to sensitive data exposure. This includes the need to ensure data protection in transit and at rest.",
		CWEs:        []string{"CWE-261", "CWE-296", "CWE-310", "CWE-319", "CWE-321", "CWE-322", "CWE-323", "CWE-324", "CWE-325", "CWE-326", "CWE-327", "CWE-328", "CWE-329", "CWE-330", "CWE-331", "CWE-335", "CWE-336", "CWE-337", "CWE-338", "CWE-339", "CWE-340", "CWE-347", "CWE-523", "CWE-720", "CWE-757", "CWE-759", "CWE-760", "CWE-780", "CWE-818", "CWE-916"},
		Remediation: "Classify data. Apply controls per classification. Don't store sensitive data unnecessarily. Encrypt all sensitive data at rest. Encrypt data in transit with TLS. Disable caching for sensitive data. Use strong algorithms and keys.",
	},
	"A03:2025": {
		ID:          "A03:2025",
		Version:     "2025",
		Name:        "Injection",
		Description: "An application is vulnerable to attack when user-supplied data is not validated, filtered, or sanitized by the application, or dynamic queries or non-parameterized calls without context-aware escaping are used directly in the interpreter.",
		CWEs:        []string{"CWE-20", "CWE-74", "CWE-75", "CWE-77", "CWE-78", "CWE-79", "CWE-80", "CWE-83", "CWE-87", "CWE-88", "CWE-89", "CWE-90", "CWE-91", "CWE-93", "CWE-94", "CWE-95", "CWE-96", "CWE-97", "CWE-98", "CWE-99", "CWE-100", "CWE-113", "CWE-116", "CWE-138", "CWE-184", "CWE-470", "CWE-471", "CWE-564", "CWE-610", "CWE-643", "CWE-644", "CWE-652", "CWE-917"},
		Remediation: "Use a safe API which avoids using the interpreter entirely. Use positive server-side input validation. Escape special characters. Use LIMIT in SQL to prevent mass disclosure.",
	},
	"A04:2025": {
		ID:          "A04:2025",
		Version:     "2025",
		Name:        "Insecure Design",
		Description: "Insecure design is a broad category representing different weaknesses, expressed as missing or ineffective control design. It is differentiated from implementation flaws.",
		CWEs:        []string{"CWE-73", "CWE-183", "CWE-209", "CWE-213", "CWE-235", "CWE-256", "CWE-257", "CWE-266", "CWE-269", "CWE-280", "CWE-311", "CWE-312", "CWE-313", "CWE-316", "CWE-419", "CWE-430", "CWE-434", "CWE-444", "CWE-451", "CWE-472", "CWE-501", "CWE-522", "CWE-525", "CWE-539", "CWE-579", "CWE-598", "CWE-602", "CWE-642", "CWE-646", "CWE-650", "CWE-653", "CWE-656", "CWE-657", "CWE-799", "CWE-807", "CWE-840", "CWE-841", "CWE-927", "CWE-1021", "CWE-1173"},
		Remediation: "Establish and use a secure development lifecycle. Use threat modeling for critical authentication, access control, business logic, and key flows. Integrate security language and controls into user stories. Write unit and integration tests.",
	},
	"A05:2025": {
		ID:          "A05:2025",
		Version:     "2025",
		Name:        "Security Misconfiguration",
		Description: "The application might be vulnerable if it is missing appropriate security hardening across any part of the application stack or has improperly configured permissions on cloud services.",
		CWEs:        []string{"CWE-2", "CWE-11", "CWE-13", "CWE-15", "CWE-16", "CWE-260", "CWE-315", "CWE-520", "CWE-526", "CWE-537", "CWE-541", "CWE-547", "CWE-611", "CWE-614", "CWE-756", "CWE-776", "CWE-942", "CWE-1004", "CWE-1032", "CWE-1174"},
		Remediation: "A repeatable hardening process. A minimal platform without unnecessary features. Review and update configurations. A segmented application architecture. Sending security directives to clients. An automated process to verify configurations.",
	},
	"A06:2025": {
		ID:          "A06:2025",
		Version:     "2025",
		Name:        "Vulnerable and Outdated Components",
		Description: "You are likely vulnerable if you do not know the versions of all components you use, if the software is vulnerable or unsupported, if you do not scan for vulnerabilities regularly, or do not fix or upgrade the underlying platform in a timely fashion.",
		CWEs:        []string{"CWE-1035", "CWE-1104"},
		Remediation: "Remove unused dependencies. Continuously inventory client-side and server-side components. Monitor for vulnerabilities. Only obtain components from official sources. Monitor for unmaintained libraries.",
	},
	"A07:2025": {
		ID:          "A07:2025",
		Version:     "2025",
		Name:        "Identification and Authentication Failures",
		Description: "Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks.",
		CWEs:        []string{"CWE-255", "CWE-259", "CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-295", "CWE-297", "CWE-300", "CWE-302", "CWE-304", "CWE-306", "CWE-307", "CWE-346", "CWE-384", "CWE-521", "CWE-613", "CWE-620", "CWE-640", "CWE-798", "CWE-940", "CWE-1216"},
		Remediation: "Implement multi-factor authentication. Do not deploy with default credentials. Implement weak password checks. Align password policies with NIST 800-63b. Harden against enumeration attacks. Limit failed login attempts. Use server-side session manager.",
	},
	"A08:2025": {
		ID:          "A08:2025",
		Version:     "2025",
		Name:        "Software and Data Integrity Failures",
		Description: "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. This includes insecure deserialization.",
		CWEs:        []string{"CWE-345", "CWE-353", "CWE-426", "CWE-494", "CWE-502", "CWE-565", "CWE-784", "CWE-829", "CWE-830", "CWE-913"},
		Remediation: "Use digital signatures. Verify software and data are from expected source. Ensure libraries are from trusted repositories. Use software composition analysis. Review code and config changes. Ensure CI/CD pipeline has proper segregation and access control.",
	},
	"A09:2025": {
		ID:          "A09:2025",
		Version:     "2025",
		Name:        "Security Logging and Monitoring Failures",
		Description: "This category helps detect, escalate, and respond to active breaches. Without logging and monitoring, breaches cannot be detected.",
		CWEs:        []string{"CWE-117", "CWE-223", "CWE-532", "CWE-778"},
		Remediation: "Ensure all login, access control, and server-side input validation failures are logged. Ensure logs are in a format for log management solutions. Ensure high-value transactions have audit trail. Establish effective monitoring and alerting. Establish incident response and recovery plan.",
	},
	"A10:2025": {
		ID:          "A10:2025",
		Version:     "2025",
		Name:        "Server-Side Request Forgery (SSRF)",
		Description: "SSRF flaws occur whenever a web application fetches a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination.",
		CWEs:        []string{"CWE-918"},
		Remediation: "Segment remote resource access. Enforce 'deny by default' firewall policies. Sanitize and validate all client-supplied input data. Do not send raw responses to clients. Disable HTTP redirections. Be aware of URL consistency to avoid DNS rebinding.",
	},
}

// Risks with full metadata including CVSS scores and incidence rates
var risks = map[string]Risk{
	"A01:2021": {
		Category:      categories["A01:2021"],
		Rank:          1,
		IncidenceRate: "3.81%",
		AvgCVSS:       6.92,
		MaxCVSS:       10.0,
		CommonCWEs: []CWE{
			{ID: "CWE-200", Name: "Exposure of Sensitive Information", Description: "The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information."},
			{ID: "CWE-284", Name: "Improper Access Control", Description: "The software does not restrict or incorrectly restricts access to a resource from an unauthorized actor."},
			{ID: "CWE-285", Name: "Improper Authorization", Description: "The software does not perform or incorrectly performs an authorization check."},
		},
	},
	"A02:2021": {
		Category:      categories["A02:2021"],
		Rank:          2,
		IncidenceRate: "2.62%",
		AvgCVSS:       7.23,
		MaxCVSS:       10.0,
		CommonCWEs: []CWE{
			{ID: "CWE-259", Name: "Use of Hard-coded Password", Description: "The software contains a hard-coded password."},
			{ID: "CWE-327", Name: "Use of Broken Crypto Algorithm", Description: "The use of a broken or risky cryptographic algorithm."},
			{ID: "CWE-331", Name: "Insufficient Entropy", Description: "The software uses an algorithm that produces insufficient entropy."},
		},
	},
	"A03:2021": {
		Category:      categories["A03:2021"],
		Rank:          3,
		IncidenceRate: "3.37%",
		AvgCVSS:       7.25,
		MaxCVSS:       10.0,
		CommonCWEs: []CWE{
			{ID: "CWE-79", Name: "Cross-site Scripting (XSS)", Description: "The software does not neutralize user-controllable input before output."},
			{ID: "CWE-89", Name: "SQL Injection", Description: "The software constructs SQL commands using externally-influenced input."},
			{ID: "CWE-78", Name: "OS Command Injection", Description: "The software constructs OS commands using externally-influenced input."},
		},
	},
	"A10:2021": {
		Category:      categories["A10:2021"],
		Rank:          10,
		IncidenceRate: "2.72%",
		AvgCVSS:       8.28,
		MaxCVSS:       10.0,
		CommonCWEs: []CWE{
			{ID: "CWE-918", Name: "Server-Side Request Forgery", Description: "The web server receives a URL from an upstream component and retrieves its contents without validating it."},
		},
	},

	// OWASP Top 10 2025 Risks
	"A01:2025": {
		Category:      categories["A01:2025"],
		Rank:          1,
		IncidenceRate: "3.81%",
		AvgCVSS:       6.92,
		MaxCVSS:       10.0,
		CommonCWEs: []CWE{
			{ID: "CWE-200", Name: "Exposure of Sensitive Information", Description: "The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information."},
			{ID: "CWE-284", Name: "Improper Access Control", Description: "The software does not restrict or incorrectly restricts access to a resource from an unauthorized actor."},
			{ID: "CWE-285", Name: "Improper Authorization", Description: "The software does not perform or incorrectly performs an authorization check."},
		},
	},
	"A02:2025": {
		Category:      categories["A02:2025"],
		Rank:          2,
		IncidenceRate: "2.62%",
		AvgCVSS:       7.23,
		MaxCVSS:       10.0,
		CommonCWEs: []CWE{
			{ID: "CWE-259", Name: "Use of Hard-coded Password", Description: "The software contains a hard-coded password."},
			{ID: "CWE-327", Name: "Use of Broken Crypto Algorithm", Description: "The use of a broken or risky cryptographic algorithm."},
			{ID: "CWE-331", Name: "Insufficient Entropy", Description: "The software uses an algorithm that produces insufficient entropy."},
		},
	},
	"A03:2025": {
		Category:      categories["A03:2025"],
		Rank:          3,
		IncidenceRate: "3.37%",
		AvgCVSS:       7.25,
		MaxCVSS:       10.0,
		CommonCWEs: []CWE{
			{ID: "CWE-79", Name: "Cross-site Scripting (XSS)", Description: "The software does not neutralize user-controllable input before output."},
			{ID: "CWE-89", Name: "SQL Injection", Description: "The software constructs SQL commands using externally-influenced input."},
			{ID: "CWE-78", Name: "OS Command Injection", Description: "The software constructs OS commands using externally-influenced input."},
		},
	},
	"A10:2025": {
		Category:      categories["A10:2025"],
		Rank:          10,
		IncidenceRate: "2.72%",
		AvgCVSS:       8.28,
		MaxCVSS:       10.0,
		CommonCWEs: []CWE{
			{ID: "CWE-918", Name: "Server-Side Request Forgery", Description: "The web server receives a URL from an upstream component and retrieves its contents without validating it."},
		},
	},
}

// GetSeverityForCategory returns a suggested severity based on the Top 10 category.
func GetSeverityForCategory(id string) string {
	risk := GetRisk(id)
	if risk == nil {
		return "medium"
	}

	if risk.AvgCVSS >= 9.0 {
		return "critical"
	} else if risk.AvgCVSS >= 7.0 {
		return "high"
	} else if risk.AvgCVSS >= 4.0 {
		return "medium"
	}
	return "low"
}

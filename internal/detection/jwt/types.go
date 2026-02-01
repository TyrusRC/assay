package jwt

import (
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
)

// VulnerabilityType represents the type of JWT vulnerability detected.
type VulnerabilityType string

const (
	// VulnNoneAlgorithm indicates the none algorithm bypass vulnerability (CVE-2015-2951).
	VulnNoneAlgorithm VulnerabilityType = "none_algorithm"
	// VulnWeakSecret indicates a weak or guessable secret was used.
	VulnWeakSecret VulnerabilityType = "weak_secret"
	// VulnAlgorithmConfusion indicates algorithm confusion attack (CVE-2015-9235).
	VulnAlgorithmConfusion VulnerabilityType = "algorithm_confusion"
	// VulnJWKInjection indicates JWK header injection vulnerability.
	VulnJWKInjection VulnerabilityType = "jwk_injection"
	// VulnJKUInjection indicates jku URL injection vulnerability.
	VulnJKUInjection VulnerabilityType = "jku_injection"
	// VulnX5UInjection indicates x5u URL injection vulnerability.
	VulnX5UInjection VulnerabilityType = "x5u_injection"
)

// String returns the human-readable name of the vulnerability type.
func (v VulnerabilityType) String() string {
	switch v {
	case VulnNoneAlgorithm:
		return "None Algorithm Bypass"
	case VulnWeakSecret:
		return "Weak Secret"
	case VulnAlgorithmConfusion:
		return "Algorithm Confusion"
	case VulnJWKInjection:
		return "JWK Header Injection"
	case VulnJKUInjection:
		return "JKU URL Injection"
	case VulnX5UInjection:
		return "X5U URL Injection"
	default:
		return string(v)
	}
}

// Severity returns the severity level for this vulnerability type.
func (v VulnerabilityType) Severity() core.Severity {
	switch v {
	case VulnNoneAlgorithm, VulnWeakSecret, VulnAlgorithmConfusion:
		return core.SeverityCritical
	case VulnJWKInjection, VulnJKUInjection, VulnX5UInjection:
		return core.SeverityHigh
	default:
		return core.SeverityMedium
	}
}

// ParsedJWT represents a parsed JWT token.
type ParsedJWT struct {
	Header    map[string]interface{}
	Claims    map[string]interface{}
	Signature string
	Algorithm string
	Raw       string
}

// IsExpired checks if the token has expired based on the exp claim.
func (p *ParsedJWT) IsExpired() bool {
	exp, ok := p.Claims["exp"]
	if !ok {
		return false // No exp claim means not expired (but this is a security issue)
	}

	expFloat, ok := exp.(float64)
	if !ok {
		return false
	}

	return time.Now().Unix() > int64(expFloat)
}

// IsNotYetValid checks if the token is not yet valid based on the nbf claim.
func (p *ParsedJWT) IsNotYetValid() bool {
	nbf, ok := p.Claims["nbf"]
	if !ok {
		return false
	}

	nbfFloat, ok := nbf.(float64)
	if !ok {
		return false
	}

	return time.Now().Unix() < int64(nbfFloat)
}

// JWTFinding represents a JWT-specific security finding.
type JWTFinding struct {
	VulnType      VulnerabilityType
	Severity      core.Severity
	Description   string
	OriginalToken string
	ModifiedToken string
	Evidence      string
	CrackedSecret string
	Remediation   string
}

// ToCoreFindings converts JWTFinding to core.Finding.
func (f *JWTFinding) ToCoreFindings(url string) *core.Finding {
	finding := core.NewFinding(f.getType(), f.Severity)
	finding.URL = url
	finding.Description = f.Description
	finding.Evidence = f.Evidence
	finding.Remediation = f.Remediation
	finding.Tool = "jwt-detector"

	// Set OWASP mappings based on vulnerability type
	finding.WithOWASPMapping(
		f.getWSTG(),
		f.getTop10(),
		f.getCWE(),
	)
	finding.APITop10 = f.getAPITop10()

	// Add metadata
	finding.Metadata["original_token"] = f.OriginalToken
	if f.ModifiedToken != "" {
		finding.Metadata["modified_token"] = f.ModifiedToken
	}
	if f.CrackedSecret != "" {
		finding.Metadata["cracked_secret"] = f.CrackedSecret
	}

	return finding
}

func (f *JWTFinding) getType() string {
	switch f.VulnType {
	case VulnNoneAlgorithm:
		return "JWT None Algorithm Bypass"
	case VulnWeakSecret:
		return "JWT Weak Secret"
	case VulnAlgorithmConfusion:
		return "JWT Algorithm Confusion"
	case VulnJWKInjection:
		return "JWT JWK Header Injection"
	case VulnJKUInjection:
		return "JWT JKU URL Injection"
	case VulnX5UInjection:
		return "JWT X5U URL Injection"
	default:
		return "JWT Vulnerability"
	}
}

func (f *JWTFinding) getWSTG() []string {
	return []string{"WSTG-SESS-01", "WSTG-ATHN-04"}
}

func (f *JWTFinding) getTop10() []string {
	return []string{"A07:2021"}
}

func (f *JWTFinding) getAPITop10() []string {
	return []string{"API2:2023"}
}

func (f *JWTFinding) getCWE() []string {
	switch f.VulnType {
	case VulnNoneAlgorithm, VulnAlgorithmConfusion:
		return []string{"CWE-347", "CWE-327"}
	case VulnWeakSecret:
		return []string{"CWE-287", "CWE-521"}
	case VulnJWKInjection, VulnJKUInjection, VulnX5UInjection:
		return []string{"CWE-347", "CWE-20"}
	default:
		return []string{"CWE-287"}
	}
}

// DetectionResult contains the results of JWT vulnerability detection.
type DetectionResult struct {
	Token       string
	Parsed      *ParsedJWT
	Findings    []*JWTFinding
	Analysis    *TokenAnalysis
	TestedCount int
}

// HasVulnerabilities returns true if any vulnerabilities were found.
func (r *DetectionResult) HasVulnerabilities() bool {
	return len(r.Findings) > 0
}

// TokenAnalysis contains the analysis of a JWT token.
type TokenAnalysis struct {
	Algorithm     string
	ExpiresAt     *time.Time
	NotBefore     *time.Time
	IssuedAt      *time.Time
	Issuer        string
	Subject       string
	Audience      []string
	Issues        []string
	HasExpiration bool
}

// HasIssues returns true if any issues were found during analysis.
func (a *TokenAnalysis) HasIssues() bool {
	return len(a.Issues) > 0
}

// VulnResult represents the result of a specific vulnerability check.
type VulnResult struct {
	Vulnerable    bool
	VulnType      VulnerabilityType
	Evidence      string
	CrackedSecret string
	ModifiedToken string
}

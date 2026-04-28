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
	// VulnEmbeddedJWKForge indicates a server that trusts an attacker-supplied
	// public key embedded in the token's "jwk" header (CVE-2018-0114-style).
	// Only emitted after a forged token has been replayed and accepted.
	VulnEmbeddedJWKForge VulnerabilityType = "embedded_jwk_forge"
	// VulnKidPathTraversal indicates the server resolves a "kid" header
	// containing a path-traversal sequence to a predictable empty file
	// (e.g. /dev/null) and accepts an HMAC signature computed with the
	// resulting empty key. Only emitted after replay confirmation.
	VulnKidPathTraversal VulnerabilityType = "kid_path_traversal"
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
	case VulnEmbeddedJWKForge:
		return "Embedded JWK Signature Forge"
	case VulnKidPathTraversal:
		return "Kid Header Path Traversal"
	default:
		return string(v)
	}
}

// Severity returns the severity level for this vulnerability type.
func (v VulnerabilityType) Severity() core.Severity {
	switch v {
	case VulnNoneAlgorithm, VulnWeakSecret, VulnAlgorithmConfusion,
		VulnEmbeddedJWKForge, VulnKidPathTraversal:
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
	// Confirmed is true when the vulnerability was verified by replaying
	// a forged token against the live server (DetectWithReplay) or by
	// proving it directly (e.g. cracking the HMAC secret). Static-only
	// observations — seeing alg:none in a token, or RS256 with a public
	// key available — start as Confirmed=false because neither is
	// exploitable on its own.
	Confirmed bool
}

// requiresReplayConfirmation returns whether this vuln class needs a
// live-server replay to be considered confirmed. Pure static observations
// (alg:none, alg confusion setup) need it; direct proofs (cracked secret,
// key-injection headers present) do not.
func (f *JWTFinding) requiresReplayConfirmation() bool {
	switch f.VulnType {
	case VulnNoneAlgorithm, VulnAlgorithmConfusion:
		return true
	default:
		return false
	}
}

// downgradedSeverity lowers an unconfirmed finding's effective severity so
// it is not reported at the same level as a proven vulnerability.
func downgradedSeverity(s core.Severity) core.Severity {
	switch s {
	case core.SeverityCritical:
		return core.SeverityMedium
	case core.SeverityHigh:
		return core.SeverityLow
	default:
		return core.SeverityInfo
	}
}

// ToCoreFindings converts JWTFinding to core.Finding.
func (f *JWTFinding) ToCoreFindings(url string) *core.Finding {
	severity := f.Severity
	description := f.Description
	evidence := f.Evidence

	// Unconfirmed static observations: downgrade severity and prefix the
	// text so consumers can't mistake a token inspection for a proven
	// server-side vulnerability.
	if !f.Confirmed && f.requiresReplayConfirmation() {
		severity = downgradedSeverity(severity)
		description = "[unconfirmed — static token inspection only; replay-verify to promote] " + description
		evidence = "[unconfirmed] " + evidence
	}

	finding := core.NewFinding(f.getType(), severity)
	finding.URL = url
	finding.Description = description
	finding.Evidence = evidence
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
	if f.Confirmed {
		finding.Metadata["confirmed"] = "true"
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
	case VulnEmbeddedJWKForge:
		return "JWT Embedded JWK Signature Forge"
	case VulnKidPathTraversal:
		return "JWT Kid Header Path Traversal"
	default:
		return "JWT Vulnerability"
	}
}

func (f *JWTFinding) getWSTG() []string {
	return []string{"WSTG-SESS-01", "WSTG-ATHN-04"}
}

func (f *JWTFinding) getTop10() []string {
	return []string{"A07:2025"}
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
	case VulnJWKInjection, VulnJKUInjection, VulnX5UInjection,
		VulnEmbeddedJWKForge:
		return []string{"CWE-347", "CWE-20"}
	case VulnKidPathTraversal:
		return []string{"CWE-22", "CWE-347"}
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

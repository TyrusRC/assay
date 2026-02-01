// Package jwt provides JWT (JSON Web Token) vulnerability detection capabilities.
// It detects common JWT security issues including algorithm confusion attacks,
// none algorithm bypass, weak secrets, and key injection vulnerabilities.
//
// The detector implements checks for:
//   - CVE-2015-9235: Algorithm confusion (RS256 to HS256 downgrade)
//   - CVE-2015-2951: None algorithm bypass
//   - Weak/common secret detection
//   - JWK/jku/x5u header injection
//   - Token expiration and validity analysis
//
// OWASP Mappings:
//   - API2:2023 Broken Authentication
//   - A07:2021 Identification and Authentication Failures
//   - CWE-287 Improper Authentication
//   - CWE-347 Improper Verification of Cryptographic Signature
package jwt

import (
	"context"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
)

// Detector detects JWT vulnerabilities.
type Detector struct {
	weakSecrets    []string
	noneVariants   []string
	maxExpDuration time.Duration
}

// NewDetector creates a new JWT vulnerability detector.
func NewDetector() *Detector {
	return &Detector{
		weakSecrets:    defaultWeakSecrets(),
		noneVariants:   defaultNoneVariants(),
		maxExpDuration: 30 * 24 * time.Hour, // 30 days max recommended
	}
}

// Name returns the detector name.
func (d *Detector) Name() string {
	return "jwt"
}

// Description returns the detector description.
func (d *Detector) Description() string {
	return "JWT (JSON Web Token) vulnerability detector - detects algorithm confusion, none algorithm bypass, weak secrets, and key injection attacks"
}

// Detect performs comprehensive JWT vulnerability detection.
func (d *Detector) Detect(ctx context.Context, token string, publicKey *rsa.PublicKey) (*DetectionResult, error) {
	result := &DetectionResult{
		Token:    token,
		Findings: make([]*JWTFinding, 0),
	}

	// Parse the token
	parsed, err := d.ParseJWT(token)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}
	result.Parsed = parsed

	// Perform token analysis
	result.Analysis = d.AnalyzeToken(token)

	// Check for none algorithm vulnerability
	select {
	case <-ctx.Done():
		return result, ctx.Err()
	default:
	}

	noneResult := d.DetectNoneAlgorithm(token)
	if noneResult.Vulnerable {
		result.TestedCount++
		result.Findings = append(result.Findings, &JWTFinding{
			VulnType:      noneResult.VulnType,
			Severity:      noneResult.VulnType.Severity(),
			Description:   "The token uses the 'none' algorithm which bypasses signature verification entirely.",
			OriginalToken: token,
			Evidence:      noneResult.Evidence,
			Remediation:   "Ensure the server explicitly validates the algorithm and rejects 'none'. Use a whitelist of allowed algorithms.",
		})
	}

	// Check for weak secret (only for HMAC algorithms)
	select {
	case <-ctx.Done():
		return result, ctx.Err()
	default:
	}

	weakResult := d.DetectWeakSecret(token)
	result.TestedCount += len(d.weakSecrets)
	if weakResult.Vulnerable {
		result.Findings = append(result.Findings, &JWTFinding{
			VulnType:      weakResult.VulnType,
			Severity:      weakResult.VulnType.Severity(),
			Description:   "The token is signed with a weak or commonly-used secret that can be easily guessed.",
			OriginalToken: token,
			CrackedSecret: weakResult.CrackedSecret,
			Evidence:      weakResult.Evidence,
			Remediation:   "Use a cryptographically secure random secret with at least 256 bits of entropy. Consider using asymmetric algorithms (RS256, ES256) instead.",
		})
	}

	// Check for algorithm confusion (if public key provided)
	if publicKey != nil {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		confusionResult := d.DetectAlgorithmConfusion(token, publicKey)
		result.TestedCount++
		if confusionResult.Vulnerable {
			result.Findings = append(result.Findings, &JWTFinding{
				VulnType:      confusionResult.VulnType,
				Severity:      confusionResult.VulnType.Severity(),
				Description:   "The token uses RSA algorithm and the public key is available. This may allow algorithm confusion attacks (CVE-2015-9235).",
				OriginalToken: token,
				Evidence:      confusionResult.Evidence,
				Remediation:   "Validate the algorithm strictly on the server side. Do not allow algorithm switching. Use separate key pairs for different algorithms.",
			})
		}
	}

	// Check for key injection vulnerabilities
	select {
	case <-ctx.Done():
		return result, ctx.Err()
	default:
	}

	keyResult := d.DetectKeyInjection(token)
	result.TestedCount++
	if keyResult.Vulnerable {
		result.Findings = append(result.Findings, &JWTFinding{
			VulnType:      keyResult.VulnType,
			Severity:      keyResult.VulnType.Severity(),
			Description:   d.getKeyInjectionDescription(keyResult.VulnType),
			OriginalToken: token,
			Evidence:      keyResult.Evidence,
			Remediation:   "Ignore jwk, jku, and x5u headers in incoming tokens. Use a hardcoded or securely configured key store.",
		})
	}

	return result, nil
}

func (d *Detector) getKeyInjectionDescription(vulnType VulnerabilityType) string {
	switch vulnType {
	case VulnJWKInjection:
		return "The token contains an embedded JWK in the header. An attacker could supply their own public key to forge valid signatures."
	case VulnJKUInjection:
		return "The token contains a jku header pointing to an external JWKS URL. An attacker could redirect this to a malicious key server."
	case VulnX5UInjection:
		return "The token contains an x5u header pointing to an external certificate URL. An attacker could redirect this to a malicious certificate."
	default:
		return "The token contains a potentially dangerous key reference in the header."
	}
}

// createFinding creates a core.Finding from JWT vulnerability detection.
func (d *Detector) createFinding(vulnType VulnerabilityType, url, originalToken, modifiedToken, evidence string) *core.Finding {
	jwtFinding := &JWTFinding{
		VulnType:      vulnType,
		Severity:      vulnType.Severity(),
		Description:   evidence,
		OriginalToken: originalToken,
		ModifiedToken: modifiedToken,
		Evidence:      evidence,
		Remediation:   d.getRemediation(vulnType),
	}

	return jwtFinding.ToCoreFindings(url)
}

func (d *Detector) getRemediation(vulnType VulnerabilityType) string {
	switch vulnType {
	case VulnNoneAlgorithm:
		return "Reject tokens with 'none' algorithm. Implement strict algorithm validation with a whitelist of allowed algorithms."
	case VulnWeakSecret:
		return "Use a cryptographically secure random secret with at least 256 bits of entropy. Consider using asymmetric algorithms."
	case VulnAlgorithmConfusion:
		return "Validate the algorithm strictly. Do not allow algorithm switching. Use separate handling for symmetric and asymmetric algorithms."
	case VulnJWKInjection, VulnJKUInjection, VulnX5UInjection:
		return "Ignore key reference headers (jwk, jku, x5u) in incoming tokens. Use hardcoded or securely configured keys."
	default:
		return "Review JWT implementation for security best practices."
	}
}

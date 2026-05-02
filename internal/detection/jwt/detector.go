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

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
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
			Description:   "The token declares the 'none' algorithm in its header. On its own this is only an observation — it becomes exploitable only if the server accepts forged tokens with alg=none.",
			OriginalToken: token,
			Evidence:      noneResult.Evidence,
			Remediation:   "Ensure the server explicitly validates the algorithm and rejects 'none'. Use a whitelist of allowed algorithms.",
			Confirmed:     false, // needs replay verification; see DetectWithReplay
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
			Confirmed:     true, // the secret was cryptographically verified
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
				Description:   "The token uses an RSA algorithm and a public key is available. This is a prerequisite for algorithm confusion attacks (CVE-2015-9235) but does not prove the server is vulnerable without replay verification.",
				OriginalToken: token,
				Evidence:      confusionResult.Evidence,
				Remediation:   "Validate the algorithm strictly on the server side. Do not allow algorithm switching. Use separate key pairs for different algorithms.",
				Confirmed:     false, // needs replay verification; see DetectWithReplay
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
			Confirmed:     true, // header field was observed directly in the token
		})
	}

	return result, nil
}

// ReplayFunc replays a forged JWT against the live server and reports
// whether the server treats it as authenticated. Implementations typically
// substitute the forged token into the original request (header, cookie,
// or query param location) and compare the response against an unforged
// baseline — a 2xx / same-session response means the forgery was accepted.
type ReplayFunc func(ctx context.Context, forgedToken string) (accepted bool, err error)

// DetectWithReplay performs the same static checks as Detect, but for
// vulnerability classes that require server-side confirmation (alg:none
// bypass, RS-to-HS algorithm confusion) it forges a token and asks the
// caller-supplied replay callback to confirm exploitation. Only verified
// findings are marked Confirmed=true; static-only observations are still
// returned (Confirmed=false) so callers can review them.
//
// If replay is nil, DetectWithReplay behaves identically to Detect.
func (d *Detector) DetectWithReplay(ctx context.Context, token string, publicKey *rsa.PublicKey, replay ReplayFunc) (*DetectionResult, error) {
	result, err := d.Detect(ctx, token, publicKey)
	if err != nil || replay == nil {
		return result, err
	}

	// Walk findings and promote or drop each replay-verifiable one.
	confirmed := make([]*JWTFinding, 0, len(result.Findings))
	for _, f := range result.Findings {
		if !f.requiresReplayConfirmation() {
			confirmed = append(confirmed, f)
			continue
		}

		if err := ctx.Err(); err != nil {
			return result, err
		}

		var forged string
		var genErr error
		switch f.VulnType {
		case VulnNoneAlgorithm:
			forged, genErr = d.GenerateNoneAlgToken(token, "none")
		case VulnAlgorithmConfusion:
			if publicKey == nil {
				// Can't forge without a public key — keep the unconfirmed finding.
				confirmed = append(confirmed, f)
				continue
			}
			forged, genErr = d.GenerateAlgConfusionToken(token, publicKey)
		}
		if genErr != nil {
			// Generation failed — keep the unconfirmed observation so
			// callers don't silently lose the signal.
			confirmed = append(confirmed, f)
			continue
		}

		accepted, replayErr := replay(ctx, forged)
		if replayErr != nil {
			// Replay error: preserve unconfirmed finding; surface the
			// error text in evidence so users know verification failed.
			f.Evidence = fmt.Sprintf("%s (replay error: %v)", f.Evidence, replayErr)
			confirmed = append(confirmed, f)
			continue
		}
		if !accepted {
			// Server rejected the forgery — drop the finding to avoid
			// false positives. The static observation alone isn't worth
			// reporting once we've proven the server isn't vulnerable.
			continue
		}

		// Server accepted the forged token: promote to confirmed.
		f.Confirmed = true
		f.ModifiedToken = forged
		f.Description = d.confirmedDescription(f.VulnType)
		f.Evidence = fmt.Sprintf("Server accepted forged token: %s", f.Evidence)
		confirmed = append(confirmed, f)
	}

	// Try the advanced forgery techniques. These are NOT reported on static
	// inspection alone — only when the server actually accepts the forgery,
	// because the false-positive rate of "server might be vulnerable" without
	// proof would dwarf any signal.
	advanced := d.attemptAdvancedForgeries(ctx, token, replay)
	confirmed = append(confirmed, advanced...)

	result.Findings = confirmed
	return result, nil
}

// attemptAdvancedForgeries runs the bug-bounty-grade forgery primitives
// (embedded JWK, kid path traversal) and returns findings only for the
// ones the server demonstrably accepted. Each primitive is one replay.
func (d *Detector) attemptAdvancedForgeries(ctx context.Context, token string, replay ReplayFunc) []*JWTFinding {
	if replay == nil {
		return nil
	}

	type attempt struct {
		vuln    VulnerabilityType
		forge   func() (string, error)
		summary string
	}
	attempts := []attempt{
		{
			vuln:    VulnEmbeddedJWKForge,
			forge:   func() (string, error) { return d.GenerateEmbeddedJWKToken(token) },
			summary: "Server accepted a token signed with an attacker-supplied JWK embedded in the header.",
		},
		{
			vuln:    VulnKidPathTraversal,
			forge:   func() (string, error) { return d.GenerateKidTraversalToken(token) },
			summary: "Server accepted an HMAC-signed token whose kid header pointed at /dev/null via path traversal, proving an empty key was used for verification.",
		},
	}

	out := make([]*JWTFinding, 0, len(attempts))
	for _, a := range attempts {
		if err := ctx.Err(); err != nil {
			return out
		}
		forged, err := a.forge()
		if err != nil {
			continue
		}
		accepted, replayErr := replay(ctx, forged)
		if replayErr != nil || !accepted {
			continue
		}
		out = append(out, &JWTFinding{
			VulnType:      a.vuln,
			Severity:      a.vuln.Severity(),
			Description:   d.confirmedDescription(a.vuln),
			OriginalToken: token,
			ModifiedToken: forged,
			Evidence:      a.summary,
			Remediation:   d.getRemediation(a.vuln),
			Confirmed:     true,
		})
	}
	return out
}

// confirmedDescription returns the verified-exploit description for a
// replay-confirmed vulnerability.
func (d *Detector) confirmedDescription(v VulnerabilityType) string {
	switch v {
	case VulnNoneAlgorithm:
		return "The server accepted a forged token with the 'none' algorithm (CVE-2015-2951). Authentication is fully bypassable."
	case VulnAlgorithmConfusion:
		return "The server accepted an HS256-signed token forged using the RSA public key as HMAC secret (CVE-2015-9235). Authentication is forgeable."
	case VulnEmbeddedJWKForge:
		return "The server pulled the verification key from a 'jwk' header inside the token itself (CVE-2018-0114-class). Any attacker can mint valid tokens by embedding their own public key. Authentication is fully forgeable."
	case VulnKidPathTraversal:
		return "The server resolved the 'kid' header against the filesystem and accepted an HMAC signature computed with an empty key (because the traversal resolved to /dev/null). Any attacker who knows the application can mint valid tokens. Authentication is fully forgeable."
	default:
		return "Verified exploitable by replay."
	}
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
	case VulnJWKInjection, VulnJKUInjection, VulnX5UInjection,
		VulnEmbeddedJWKForge:
		return "Ignore key reference headers (jwk, jku, x5u) in incoming tokens. Resolve verification keys only from a trusted, server-side keystore."
	case VulnKidPathTraversal:
		return "Treat 'kid' as an opaque identifier, not a filesystem path. Resolve it through a fixed lookup table and reject values containing path separators or traversal sequences."
	default:
		return "Review JWT implementation for security best practices."
	}
}

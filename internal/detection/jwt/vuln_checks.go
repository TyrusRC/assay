package jwt

import (
	"crypto/rsa"
	"fmt"
	"strings"
	"time"
)

// excessiveLifetime is the threshold beyond which we consider an exp
// claim "long-lived". 365 days × 24 hours; tokens with exp further out
// than this are practically equivalent to non-expiring once leaked.
const excessiveLifetime = 365 * 24 * time.Hour

// DetectExpirationIssues inspects the exp / nbf / iat claims for
// lifetime-related weaknesses. Two grades are emitted:
//   - VulnNoExpiration when the exp claim is absent entirely.
//   - VulnLongLivedToken when iat-to-exp window exceeds excessiveLifetime
//     (or, when iat is missing, exp is more than excessiveLifetime in
//     the future from now).
//
// Both run in pure-static mode (no network) so this is safe to call on
// any captured token. Only the first matching weakness is returned per
// call; downstream code can inspect the same token for separate vulns.
func (d *Detector) DetectExpirationIssues(token string) *VulnResult {
	result := &VulnResult{Vulnerable: false}

	parsed, err := d.ParseJWT(token)
	if err != nil {
		return result
	}

	expRaw, expOK := parsed.Claims["exp"]
	if !expOK {
		result.Vulnerable = true
		result.VulnType = VulnNoExpiration
		result.Evidence = "JWT does not declare an `exp` claim; once issued, it is reusable indefinitely."
		return result
	}
	expFloat, ok := expRaw.(float64)
	if !ok {
		// Malformed exp — treat as missing rather than error.
		result.Vulnerable = true
		result.VulnType = VulnNoExpiration
		result.Evidence = fmt.Sprintf("JWT `exp` claim is not a numeric timestamp (got %T).", expRaw)
		return result
	}

	exp := time.Unix(int64(expFloat), 0)
	var window time.Duration
	if iatRaw, ok := parsed.Claims["iat"]; ok {
		if iatF, ok := iatRaw.(float64); ok {
			iat := time.Unix(int64(iatF), 0)
			window = exp.Sub(iat)
		}
	}
	if window == 0 {
		// No iat — fall back to "exp from now".
		window = time.Until(exp)
	}
	if window > excessiveLifetime {
		result.Vulnerable = true
		result.VulnType = VulnLongLivedToken
		result.Evidence = fmt.Sprintf(
			"JWT lifetime is %.0f days (exp at %s). Long-lived tokens behave like non-expiring credentials once leaked.",
			window.Hours()/24, exp.UTC().Format(time.RFC3339),
		)
		return result
	}
	return result
}

// DetectNoneAlgorithm checks for none algorithm bypass vulnerability.
func (d *Detector) DetectNoneAlgorithm(token string) *VulnResult {
	result := &VulnResult{Vulnerable: false}

	parsed, err := d.ParseJWT(token)
	if err != nil {
		return result
	}

	// Check if algorithm is a variant of "none"
	alg := strings.ToLower(parsed.Algorithm)
	if alg == "none" {
		result.Vulnerable = true
		result.VulnType = VulnNoneAlgorithm
		result.Evidence = fmt.Sprintf("Token uses '%s' algorithm which bypasses signature verification", parsed.Algorithm)
	}

	return result
}

// DetectWeakSecret attempts to crack the JWT secret using a dictionary of common secrets.
func (d *Detector) DetectWeakSecret(token string) *VulnResult {
	result := &VulnResult{Vulnerable: false}

	parsed, err := d.ParseJWT(token)
	if err != nil {
		return result
	}

	// Only check HS256/HS384/HS512 tokens
	if !strings.HasPrefix(parsed.Algorithm, "HS") {
		return result
	}

	// Try each weak secret
	for _, secret := range d.weakSecrets {
		if d.VerifyHS256Signature(token, secret) {
			result.Vulnerable = true
			result.VulnType = VulnWeakSecret
			result.CrackedSecret = secret
			result.Evidence = fmt.Sprintf("Token signed with weak/common secret: '%s'", secret)
			return result
		}
	}

	return result
}

// DetectAlgorithmConfusion checks for RS256 to HS256 algorithm confusion vulnerability.
func (d *Detector) DetectAlgorithmConfusion(token string, publicKey *rsa.PublicKey) *VulnResult {
	result := &VulnResult{Vulnerable: false}

	parsed, err := d.ParseJWT(token)
	if err != nil {
		return result
	}

	// Only vulnerable if using RS256/RS384/RS512 and public key is available
	if !strings.HasPrefix(parsed.Algorithm, "RS") {
		return result
	}

	if publicKey == nil {
		return result
	}

	// This indicates potential for algorithm confusion attack
	result.Vulnerable = true
	result.VulnType = VulnAlgorithmConfusion
	result.Evidence = "Token uses RSA algorithm and public key is available. An attacker could potentially sign tokens using the public key as HMAC secret."

	return result
}

// DetectKeyInjection checks for JWK, jku, or x5u header injection vulnerabilities.
func (d *Detector) DetectKeyInjection(token string) *VulnResult {
	result := &VulnResult{Vulnerable: false}

	parsed, err := d.ParseJWT(token)
	if err != nil {
		return result
	}

	// Check for JWK header injection
	if _, ok := parsed.Header["jwk"]; ok {
		result.Vulnerable = true
		result.VulnType = VulnJWKInjection
		result.Evidence = "Token contains embedded JWK in header. This could allow an attacker to supply their own public key for verification."
		return result
	}

	// Check for jku URL injection
	if jku, ok := parsed.Header["jku"]; ok {
		result.Vulnerable = true
		result.VulnType = VulnJKUInjection
		result.Evidence = fmt.Sprintf("Token contains jku header pointing to: %v. An attacker could potentially redirect to a malicious JWKS endpoint.", jku)
		return result
	}

	// Check for x5u URL injection
	if x5u, ok := parsed.Header["x5u"]; ok {
		result.Vulnerable = true
		result.VulnType = VulnX5UInjection
		result.Evidence = fmt.Sprintf("Token contains x5u header pointing to: %v. An attacker could potentially redirect to a malicious certificate URL.", x5u)
		return result
	}

	return result
}

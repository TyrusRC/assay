package jwt

import (
	"crypto/rsa"
	"fmt"
	"strings"
)

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

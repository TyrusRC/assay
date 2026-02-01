// Package jwt provides JWT (JSON Web Token) vulnerability detection capabilities.
//
// This package implements detection for common JWT security vulnerabilities including:
//
// # Algorithm Confusion (CVE-2015-9235)
//
// Algorithm confusion attacks exploit systems that use RSA-based algorithms (RS256)
// but can be tricked into accepting HMAC-based signatures (HS256) using the public
// key as the HMAC secret. This is possible when servers do not properly validate
// the algorithm specified in the token header.
//
// # None Algorithm Bypass (CVE-2015-2951)
//
// The "none" algorithm bypass exploits systems that accept tokens with the algorithm
// set to "none" (case-insensitive variants), effectively bypassing signature
// verification entirely. This allows attackers to forge arbitrary tokens.
//
// # Weak Secret Detection
//
// Tests for commonly used weak secrets such as "secret", "password", "123456", etc.
// Weak secrets can be cracked through dictionary attacks, allowing attackers to
// forge valid tokens.
//
// # Key Injection Vulnerabilities
//
// Detects dangerous header claims that could allow key injection:
//   - jwk: Embedded JSON Web Key in the header
//   - jku: URL to a JSON Web Key Set
//   - x5u: URL to an X.509 certificate chain
//
// These allow attackers to supply their own keys for signature verification.
//
// # Token Analysis
//
// Performs comprehensive analysis of JWT tokens including:
//   - Expiration (exp) claim validation
//   - Not Before (nbf) claim validation
//   - Issued At (iat) claim checking
//   - Algorithm validation
//   - Security best practice checks
//
// # OWASP Mappings
//
// Vulnerabilities detected by this package map to:
//   - WSTG-SESS-01: Testing for Session Management Schema
//   - WSTG-ATHN-04: Testing for Authentication
//   - API2:2023: Broken Authentication
//   - A07:2021: Identification and Authentication Failures
//   - CWE-287: Improper Authentication
//   - CWE-347: Improper Verification of Cryptographic Signature
//   - CWE-327: Use of a Broken or Risky Cryptographic Algorithm
//   - CWE-521: Weak Password Requirements
//
// # Usage
//
// Basic usage:
//
//	detector := jwt.NewDetector()
//	result, err := detector.Detect(ctx, tokenString, nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if result.HasVulnerabilities() {
//	    for _, finding := range result.Findings {
//	        fmt.Printf("Found: %s (%s)\n", finding.VulnType, finding.Severity)
//	    }
//	}
//
// With public key for algorithm confusion testing:
//
//	result, err := detector.Detect(ctx, tokenString, publicKey)
//
// Individual vulnerability checks:
//
//	noneResult := detector.DetectNoneAlgorithm(token)
//	weakResult := detector.DetectWeakSecret(token)
//	keyResult := detector.DetectKeyInjection(token)
//
// Token analysis:
//
//	analysis := detector.AnalyzeToken(token)
//	if analysis.HasIssues() {
//	    for _, issue := range analysis.Issues {
//	        fmt.Println(issue)
//	    }
//	}
package jwt

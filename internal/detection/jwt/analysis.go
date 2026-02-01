package jwt

import (
	"fmt"
	"time"
)

// AnalyzeToken performs a comprehensive analysis of the JWT token.
func (d *Detector) AnalyzeToken(token string) *TokenAnalysis {
	analysis := &TokenAnalysis{
		Issues: make([]string, 0),
	}

	parsed, err := d.ParseJWT(token)
	if err != nil {
		analysis.Issues = append(analysis.Issues, fmt.Sprintf("Failed to parse token: %v", err))
		return analysis
	}

	analysis.Algorithm = parsed.Algorithm

	// Check expiration claim
	if exp, ok := parsed.Claims["exp"]; ok {
		analysis.HasExpiration = true
		if expFloat, ok := exp.(float64); ok {
			expTime := time.Unix(int64(expFloat), 0)
			analysis.ExpiresAt = &expTime

			if parsed.IsExpired() {
				analysis.Issues = append(analysis.Issues, "Token is expired")
			}

			// Check for very long expiration
			if time.Until(expTime) > d.maxExpDuration {
				analysis.Issues = append(analysis.Issues, fmt.Sprintf("Token has very long expiration (>%v)", d.maxExpDuration))
			}
		}
	} else {
		analysis.Issues = append(analysis.Issues, "Token is missing exp claim - tokens should have expiration")
	}

	// Check not before claim
	if nbf, ok := parsed.Claims["nbf"]; ok {
		if nbfFloat, ok := nbf.(float64); ok {
			nbfTime := time.Unix(int64(nbfFloat), 0)
			analysis.NotBefore = &nbfTime

			if parsed.IsNotYetValid() {
				analysis.Issues = append(analysis.Issues, "Token is not yet valid (nbf claim is in future)")
			}
		}
	}

	// Check issued at claim
	if iat, ok := parsed.Claims["iat"]; ok {
		if iatFloat, ok := iat.(float64); ok {
			iatTime := time.Unix(int64(iatFloat), 0)
			analysis.IssuedAt = &iatTime
		}
	}

	// Extract other standard claims
	if iss, ok := parsed.Claims["iss"].(string); ok {
		analysis.Issuer = iss
	}
	if sub, ok := parsed.Claims["sub"].(string); ok {
		analysis.Subject = sub
	}

	return analysis
}

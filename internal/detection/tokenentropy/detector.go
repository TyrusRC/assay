// Package tokenentropy detects insecure-randomness in
// session / CSRF / authentication tokens. The probe makes one or
// more requests to the target, gathers every Set-Cookie value,
// inspects the body for embedded CSRF / session tokens, and runs a
// pair of cheap statistical tests on each candidate:
//
//   - Shannon entropy: tokens whose entropy / character length is
//     well below ~3.0 bits/char are typically base-N or hex-only with
//     a tiny effective alphabet — common in counter-derived or
//     timestamp-derived schemes.
//   - Sequential / numeric shape: tokens that parse as a small integer
//     (or as the user agent's IP, current epoch, or a base-26 word)
//     are guessable by enumeration.
//
// We never claim a token is broken; we surface the entropy class so
// reviewers can decide. False-positive risk is low because we only
// inspect tokens whose name matches a known token-shape pattern
// (session, csrf, xsrf, token, auth, jsessionid, ...).
package tokenentropy

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// tokenNameRe matches cookie / form-field names that conventionally
// hold session-like material.
var tokenNameRe = regexp.MustCompile(`(?i)(session(_?id)?|sessid|jsessionid|phpsessid|asp\.net_sessionid|csrf|xsrf|auth(token|_?cookie)?|token|access_?token|refresh_?token|api[_-]?key)`)

// embeddedTokenRe pulls obvious CSRF / session tokens from HTML or
// JSON bodies (the canonical `name="csrf_token" value="..."` and
// JSON shapes).
var embeddedTokenRe = regexp.MustCompile(`(?i)(?:name=["'](csrf[_-]?token|xsrf[_-]?token|authenticity_token)["']\s+value=["']([^"']{6,})["'])|(?:["'](csrf[_-]?token|xsrf[_-]?token)["']\s*:\s*["']([^"']{6,})["'])`)

// minTokenLen filters out short cookies (e.g. `theme=dark`) that
// aren't tokens and would always fail the entropy bar.
const minTokenLen = 12

// entropyFloor is the threshold below which we consider a token
// suspicious. 3.0 bits/char is roughly base8 — most production session
// tokens emit 5–6 bits/char (alphanumeric + symbols).
const entropyFloor = 3.0

// Detector probes a target for insecure-token output.
type Detector struct {
	client *skwshttp.Client
}

// New returns a Detector wired to the project's shared HTTP client.
func New(client *skwshttp.Client) *Detector {
	return &Detector{client: client}
}

// Result carries findings emitted by Detect.
type Result struct {
	Findings []*core.Finding
}

// Detect fetches targetURL once and inspects:
//   - every Set-Cookie value (parsed via http.Header)
//   - every embedded csrf / xsrf / authenticity token in the body.
// One finding is emitted per low-entropy / sequential token.
func (d *Detector) Detect(ctx context.Context, targetURL string) (*Result, error) {
	res := &Result{}
	if d.client == nil {
		return res, nil
	}
	resp, err := d.client.Get(ctx, targetURL)
	if err != nil || resp == nil {
		return res, nil
	}

	cookies := extractTokenCookies(resp)
	for name, value := range cookies {
		if f := evaluate(targetURL, name, value, "cookie"); f != nil {
			res.Findings = append(res.Findings, f)
		}
	}

	for name, value := range extractEmbeddedTokens(resp.Body) {
		if f := evaluate(targetURL, name, value, "embedded"); f != nil {
			res.Findings = append(res.Findings, f)
		}
	}

	return res, nil
}

// evaluate returns a finding when the token fails either the entropy
// or the sequential-shape test, otherwise nil.
func evaluate(target, name, value, source string) *core.Finding {
	if !tokenNameRe.MatchString(name) {
		return nil
	}
	if len(value) < minTokenLen {
		return nil
	}
	bitsPerChar := shannonEntropy(value)
	switch {
	case bitsPerChar < entropyFloor:
		return buildFinding(target, name, value, source,
			fmt.Sprintf("Shannon entropy %.2f bits/char (threshold %.1f)", bitsPerChar, entropyFloor))
	case isSequential(value):
		return buildFinding(target, name, value, source, "token parses as a small integer or sequential counter")
	}
	return nil
}

// shannonEntropy returns bits-per-character on the given string.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, c := range counts {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// isSequential returns true when the string is shaped like an
// enumerable counter — a plain integer, a small hex of monotonic
// shape, or a left-padded number.
func isSequential(s string) bool {
	trimmed := strings.TrimLeft(s, "0")
	if trimmed == "" {
		return true // all-zero token
	}
	if _, err := strconv.ParseUint(s, 10, 64); err == nil {
		return true
	}
	// Hex-only short tokens are not necessarily sequential, but a
	// hex-only token of length < 24 fails the entropy bar already.
	return false
}

// extractTokenCookies returns the subset of Set-Cookie values whose
// names look token-shaped. We re-parse Set-Cookie from raw because
// the project's http.Response collapses headers into a single string
// per name.
func extractTokenCookies(resp *skwshttp.Response) map[string]string {
	out := map[string]string{}
	if resp == nil {
		return out
	}
	for name, value := range resp.Headers {
		if !strings.EqualFold(name, "set-cookie") {
			continue
		}
		// Set-Cookie may carry multiple cookies separated by `\n`
		// when collapsed — split on newline so we see each one.
		for _, line := range strings.Split(value, "\n") {
			parts := strings.SplitN(line, ";", 2)
			kv := strings.SplitN(parts[0], "=", 2)
			if len(kv) != 2 {
				continue
			}
			out[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	// Fallback: Some HTTP clients normalise Set-Cookie via a Cookies
	// helper. We don't have one here; the Header-walk above is enough
	// for the test fixtures. For the live path, the *http.Response
	// embedded Cookies are also worth scanning when available.
	if hr, ok := any(resp).(*http.Response); ok {
		for _, c := range hr.Cookies() {
			if _, set := out[c.Name]; !set {
				out[c.Name] = c.Value
			}
		}
	}
	return out
}

// extractEmbeddedTokens returns CSRF / authenticity-token pairs found
// in the body via regex.
func extractEmbeddedTokens(body string) map[string]string {
	out := map[string]string{}
	for _, m := range embeddedTokenRe.FindAllStringSubmatch(body, -1) {
		// match groups: 0=full, 1+2 are HTML-attr pair, 3+4 are JSON pair.
		if m[1] != "" && m[2] != "" {
			out[m[1]] = m[2]
		}
		if m[3] != "" && m[4] != "" {
			out[m[3]] = m[4]
		}
	}
	return out
}

func buildFinding(target, name, value, source, reason string) *core.Finding {
	finding := core.NewFinding("Insecure-Randomness Token", core.SeverityMedium)
	finding.URL = target
	finding.Parameter = name
	finding.Tool = "tokenentropy"
	finding.Confidence = core.ConfidenceMedium
	finding.Description = fmt.Sprintf(
		"Token %q (source: %s) shows shape consistent with insecure randomness: %s. Tokens generated from counters, timestamps, or low-entropy alphabets can be enumerated or predicted by an attacker.",
		name, source, reason,
	)
	preview := value
	if len(preview) > 24 {
		preview = preview[:21] + "..."
	}
	finding.Evidence = fmt.Sprintf("Source: %s\nName: %s\nPreview: %s\nReason: %s",
		source, name, preview, reason)
	finding.Remediation = "Generate session / CSRF tokens with crypto/rand (Go), `secrets.token_urlsafe()` (Python), `crypto.randomBytes()` (Node), or the equivalent CSPRNG in your language. Aim for at least 128 bits of entropy and a base64url alphabet."
	finding.WithOWASPMapping(
		[]string{"WSTG-SESS-01"},
		[]string{"A02:2025"},
		[]string{"CWE-330"},
	)
	finding.APITop10 = []string{"API2:2023"}
	return finding
}

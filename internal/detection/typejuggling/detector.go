// Package typejuggling detects PHP / loose-equality type-juggling
// authentication bypass on login-shaped endpoints. Two probe shapes
// are sent:
//
//   - Array-coerced password: `?password[]=` makes the server-side
//     compare receive an array; PHP's `==` returns NULL == any-string
//     === true, so loose comparisons against the stored hash succeed.
//   - Magic-hash collisions: `0e1`, `0e0`, `"0"` — strings PHP coerces
//     to the same float (0.0) when compared with `==`. A stored hash
//     starting with `0e<digits>` collides with any of these.
//
// Detection pivots on a baseline-differential comparison: send a
// known-bad password (random string), then send each magic value, and
// emit a finding when the magic-value response is materially closer
// to a "logged in" shape than the random-string response.
package typejuggling

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/analysis"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// loginPathHints flag URLs that are plausibly login endpoints. We
// don't probe arbitrary URLs — that's both noisy (every form would
// emit) and risky (POSTing to a non-login endpoint with garbage
// could mutate state).
var loginPathHints = []string{
	"login", "signin", "auth", "session", "authenticate",
}

// magicHashValues are PHP loose-equality collision candidates. Each
// is sent as the password value alongside a well-known username.
var magicHashValues = []string{"0e1", "0", "0e0", "0e215962017"}

// Detector probes a login URL for type-juggling auth bypass.
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

// Detect tests targetURL when its path looks like a login endpoint.
// Sends three probes per username: random-bad-password baseline, an
// array-coerced password, and each magic-hash value. A magic / array
// response that is materially closer to "logged in" than the random
// baseline emits a finding.
func (d *Detector) Detect(ctx context.Context, targetURL, username string) (*Result, error) {
	res := &Result{}
	if d.client == nil {
		return res, nil
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return res, nil
	}
	if !pathLooksLogin(u.Path) {
		return res, nil
	}
	if username == "" {
		username = "admin"
	}

	// Random-bad baseline (definitely-wrong password).
	badPwd := "skws-bad-" + randomToken()
	baseRespForm := d.postForm(ctx, targetURL, "username", username, "password", badPwd)
	baseRespJSON := d.postJSON(ctx, targetURL, fmt.Sprintf(`{"username":%q,"password":%q}`, username, badPwd))

	// Array-coerced password. We can only express this in form bodies;
	// JSON payloads don't have ambient PHP-style array semantics.
	if hit := d.tryProbe(ctx, targetURL, baseRespForm, formBody(map[string]string{
		"username":    username,
		"password[]": "x",
	}), "application/x-www-form-urlencoded", "array-coerced password"); hit != nil {
		res.Findings = append(res.Findings, hit)
	}

	// Magic-hash values. Form + JSON shapes both tested.
	for _, mv := range magicHashValues {
		if hit := d.tryProbe(ctx, targetURL, baseRespForm, formBody(map[string]string{
			"username": username,
			"password": mv,
		}), "application/x-www-form-urlencoded", "magic-hash form pw="+mv); hit != nil {
			res.Findings = append(res.Findings, hit)
			break
		}
		if hit := d.tryProbe(ctx, targetURL, baseRespJSON,
			fmt.Sprintf(`{"username":%q,"password":%q}`, username, mv),
			"application/json", "magic-hash json pw="+mv); hit != nil {
			res.Findings = append(res.Findings, hit)
			break
		}
	}
	return res, nil
}

// tryProbe sends body to targetURL, compares against baseline, and
// emits a finding when the probe response shape is materially
// different from baseline (Jaccard < 0.85) AND the probe response is
// shorter than baseline OR contains an obvious "logged in" marker
// (cookies, token, success). The shape divergence rules out servers
// that 200 every login attempt with the same error page.
func (d *Detector) tryProbe(ctx context.Context, target string, baseline *skwshttp.Response, body, contentType, kind string) *core.Finding {
	if baseline == nil {
		return nil
	}
	resp, err := d.client.SendRawBody(ctx, target, "POST", body, contentType)
	if err != nil || resp == nil {
		return nil
	}
	// Probe must be 2xx; 4xx response means the server rejected the shape.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}
	baseStripped := analysis.StripDynamicContent(baseline.Body)
	probeStripped := analysis.StripDynamicContent(resp.Body)
	if analysis.ResponseSimilarity(baseStripped, probeStripped) >= 0.85 {
		return nil
	}
	if !looksLoggedIn(resp) {
		return nil
	}
	return buildFinding(target, kind, baseline.StatusCode, resp.StatusCode)
}

func pathLooksLogin(path string) bool {
	lower := strings.ToLower(path)
	for _, hint := range loginPathHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

// looksLoggedIn returns true when the response shape suggests a
// successful authentication: a session-style cookie, a Bearer token,
// or "success"/"welcome" text. Tightens the probe so we never claim
// "type juggling" on servers that simply return a unique error page.
func looksLoggedIn(resp *skwshttp.Response) bool {
	for name, val := range resp.Headers {
		ln := strings.ToLower(name)
		if ln == "set-cookie" && (strings.Contains(strings.ToLower(val), "session") ||
			strings.Contains(strings.ToLower(val), "token") ||
			strings.Contains(strings.ToLower(val), "auth")) {
			return true
		}
	}
	lc := strings.ToLower(resp.Body)
	if strings.Contains(lc, "\"token\"") || strings.Contains(lc, "\"access_token\"") ||
		strings.Contains(lc, "welcome") || strings.Contains(lc, "logged in") ||
		strings.Contains(lc, "logout") || strings.Contains(lc, "dashboard") {
		return true
	}
	return false
}

func (d *Detector) postForm(ctx context.Context, target string, kvs ...string) *skwshttp.Response {
	body := strings.Builder{}
	for i := 0; i < len(kvs); i += 2 {
		if i > 0 {
			body.WriteByte('&')
		}
		body.WriteString(url.QueryEscape(kvs[i]))
		body.WriteByte('=')
		body.WriteString(url.QueryEscape(kvs[i+1]))
	}
	resp, _ := d.client.SendRawBody(ctx, target, "POST", body.String(), "application/x-www-form-urlencoded")
	return resp
}

func (d *Detector) postJSON(ctx context.Context, target, body string) *skwshttp.Response {
	resp, _ := d.client.SendRawBody(ctx, target, "POST", body, "application/json")
	return resp
}

func formBody(kv map[string]string) string {
	parts := []string{}
	for k, v := range kv {
		parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
	}
	return strings.Join(parts, "&")
}

func buildFinding(target, kind string, baseStatus, probeStatus int) *core.Finding {
	finding := core.NewFinding("Authentication Type-Juggling Bypass", core.SeverityCritical)
	finding.URL = target
	finding.Parameter = kind
	finding.Tool = "typejuggling"
	finding.Confidence = core.ConfidenceHigh
	finding.Description = fmt.Sprintf(
		"The login endpoint produced a logged-in response shape for the %s probe but rejected the random-bad-password baseline. The server-side comparator is using PHP-style loose equality (`==`) against the stored credential, allowing bypass via array-coerced or magic-hash collision values.",
		kind,
	)
	finding.Evidence = fmt.Sprintf("Probe shape: %s\nBaseline status: %d\nProbe status: %d\nResponse divergence + login-shaped marker observed.",
		kind, baseStatus, probeStatus)
	finding.Remediation = "Use strict-equality (`===`) when comparing credentials, or compare hashes with `hash_equals` / `password_verify`. Reject array-shaped values for scalar fields server-side. Migrate stored hashes off `0e`-prefixed values that collide under loose equality."
	finding.WithOWASPMapping(
		[]string{"WSTG-ATHN-04"},
		[]string{"A07:2025"},
		[]string{"CWE-697"},
	)
	finding.APITop10 = []string{"API2:2023"}
	return finding
}

func randomToken() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

package hosthdr

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	internalhttp "github.com/TyrusRC/assay/internal/http"
)

// legitHost is the placeholder host used for baseline requests in the
// advanced probes. It is deliberately not "example.com" — we want the
// detector's signal (presence of opts.AttackerHost) to be unambiguously
// attacker-induced rather than from a value the application might echo
// for its own reasons.
const legitHost = "legit.example.com"

// toolName is the tool tag for findings produced by AdvancedDetector
// probes. Kept distinct from the base "hosthdr-detector" so report
// consumers can disable / weight advanced findings independently.
const toolName = "hosthdr-advanced-detector"

// DetectForwardedHostConfusion checks whether the application trusts the
// X-Forwarded-Host or Forwarded (RFC 7239) headers to override the
// authoritative Host when building absolute URLs.
//
// Procedure:
//  1. Baseline GET with Host: legit.example.com.
//  2. Probe GET with Host: legit.example.com + X-Forwarded-Host: attacker.
//  3. Probe GET with Host: legit.example.com + Forwarded: host=attacker.
//
// If the attacker host appears in the probe's response body or
// Location/Link/Refresh/Content-Location header AND was absent from the
// baseline, the app honored the user-controlled forwarding header — a
// Critical cache-poisoning / password-reset hijack vector.
func (d *Detector) DetectForwardedHostConfusion(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	opts = withDefaults(opts)
	result := &DetectionResult{Findings: make([]*core.Finding, 0)}

	baseline, err := d.client.SendPayloadInHeader(ctx, target, "Host", legitHost, "GET")
	if err != nil {
		return result, fmt.Errorf("baseline request failed: %w", err)
	}

	probes := []struct {
		headers map[string]string
		via     string // human label for the carrier header
	}{
		{
			headers: map[string]string{"Host": legitHost, "X-Forwarded-Host": opts.AttackerHost},
			via:     "X-Forwarded-Host",
		},
		{
			headers: map[string]string{"Host": legitHost, "Forwarded": "host=" + opts.AttackerHost},
			via:     "Forwarded (RFC 7239)",
		},
	}

	for _, p := range probes {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}
		result.Tested++

		resp, err := d.client.Do(ctx, &internalhttp.Request{
			Method:  "GET",
			URL:     target,
			Headers: p.headers,
		})
		if err != nil {
			continue
		}
		if !attackerReflected(resp, baseline, opts.AttackerHost) {
			continue
		}

		f := newForwardedHostFinding(target, p.via, opts.AttackerHost)
		result.Findings = append(result.Findings, f)
		result.Vulnerable = true
	}

	return result, nil
}

// DetectAbsoluteURIVsHostConflict sends a raw HTTP/1.1 request whose
// request-line is an absolute-URI (per RFC 7230 §5.3.2) pointing at the
// actual target, but whose Host header points at a different attacker
// authority. A compliant server MUST prefer the absolute-URI authority.
//
// If the response indicates the server routed by Host (e.g. echoes the
// attacker host, or otherwise differs from a baseline absolute-URI
// request whose Host agrees with the URI), we flag — this is a
// well-known HTTP smuggling pre-condition (CWE-444) plus virtual-host
// confusion at proxies and origin servers.
//
// We bypass *internalhttp.Client deliberately because Go's net/http
// normalizes absolute-URI requests away before the wire, defeating the
// probe.
func (d *Detector) DetectAbsoluteURIVsHostConflict(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	opts = withDefaults(opts)
	result := &DetectionResult{Findings: make([]*core.Finding, 0)}

	u, err := url.Parse(target)
	if err != nil {
		return result, fmt.Errorf("invalid target URL: %w", err)
	}
	if u.Scheme != "http" {
		// Raw socket TLS handshake is out of scope for this detector;
		// proxy/CDN smuggling research generally focuses on cleartext
		// hops anyway. Skip silently for https targets.
		return result, nil
	}

	addr := u.Host
	if !strings.Contains(addr, ":") {
		addr = addr + ":80"
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	absoluteURI := u.Scheme + "://" + u.Host + path

	// Baseline: absolute-URI with matching Host header. This is the
	// reference response from a well-behaved server when there is no
	// header/URI conflict.
	baselineBody, err := rawHTTPRoundTrip(ctx, addr, "GET "+absoluteURI+" HTTP/1.1", map[string]string{
		"Host":       u.Host,
		"Connection": "close",
	}, opts.Timeout)
	if err != nil {
		return result, fmt.Errorf("baseline raw round-trip failed: %w", err)
	}
	result.Tested++

	// Probe: absolute-URI to the real authority, but Host: attacker.
	probeBody, err := rawHTTPRoundTrip(ctx, addr, "GET "+absoluteURI+" HTTP/1.1", map[string]string{
		"Host":       opts.AttackerHost,
		"Connection": "close",
	}, opts.Timeout)
	if err != nil {
		return result, fmt.Errorf("probe raw round-trip failed: %w", err)
	}
	result.Tested++

	atk := strings.ToLower(opts.AttackerHost)
	probeLower := strings.ToLower(probeBody)
	baselineLower := strings.ToLower(baselineBody)

	// Signal: the attacker host shows up in the probe body but NOT the
	// baseline. That means the server honored the Host header for
	// routing/templating instead of the absolute-URI authority.
	if !strings.Contains(probeLower, atk) || strings.Contains(baselineLower, atk) {
		return result, nil
	}

	f := newAbsoluteURIFinding(target, opts.AttackerHost)
	result.Findings = append(result.Findings, f)
	result.Vulnerable = true
	return result, nil
}

// DetectCachePoisoningViaHost exercises the canonical web-cache poisoning
// pattern: send a poisoned request whose X-Forwarded-Host points at the
// attacker, then issue a "clean" request from a fresh client to the same
// cache key. If the second request's body contains the attacker host,
// the cache served the poisoned response to an unrelated user.
//
// Cache-key isolation is achieved with a unique X-Cache-Bust query
// parameter so this probe never collides with real traffic against the
// same target, regardless of the proxy's normalization rules.
//
// Requires opts.CacheTestEnabled — this probe writes user-visible state
// (a poisoned cache entry) and should only run with explicit consent.
func (d *Detector) DetectCachePoisoningViaHost(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	opts = withDefaults(opts)
	result := &DetectionResult{Findings: make([]*core.Finding, 0)}
	if !opts.CacheTestEnabled {
		return result, nil
	}

	// Bust the cache key so we can both observe and clean up cleanly.
	bust, err := randomMarker()
	if err != nil {
		return result, fmt.Errorf("cache-bust marker: %w", err)
	}
	poisoned, err := appendQuery(target, "x_cache_bust", bust)
	if err != nil {
		return result, fmt.Errorf("append cache-bust query: %w", err)
	}

	// Step 1: poison. Send the attacker-controlled X-Forwarded-Host
	// against the unique cache key.
	_, err = d.client.Do(ctx, &internalhttp.Request{
		Method: "GET",
		URL:    poisoned,
		Headers: map[string]string{
			"X-Forwarded-Host": opts.AttackerHost,
		},
	})
	if err != nil {
		return result, fmt.Errorf("poison request failed: %w", err)
	}
	result.Tested++

	// Step 2: clean follow-up from a separate logical client (cloned
	// client, no forwarding header). If we get the poisoned body back,
	// the cache served a different user's would-be response.
	cleanClient := d.client.Clone()
	resp, err := cleanClient.Get(ctx, poisoned)
	if err != nil {
		return result, fmt.Errorf("clean request failed: %w", err)
	}
	result.Tested++

	atk := strings.ToLower(opts.AttackerHost)
	bodyLower := strings.ToLower(resp.Body)
	// Confirmation: the clean follow-up — which never sent the attacker
	// header — still received a body referencing the attacker host.
	if !strings.Contains(bodyLower, atk) {
		return result, nil
	}

	f := newCachePoisoningFinding(target, opts.AttackerHost)
	result.Findings = append(result.Findings, f)
	result.Vulnerable = true
	return result, nil
}

// withDefaults centralizes option fall-through so each Detect* method
// can rely on Timeout/AttackerHost being populated.
func withDefaults(opts DetectOptions) DetectOptions {
	if opts.Timeout <= 0 {
		opts.Timeout = 8 * time.Second
	}
	if opts.AttackerHost == "" {
		opts.AttackerHost = "assay-host-poison.example"
	}
	return opts
}

// attackerReflected reports whether the attacker host appears in
// indicative response surfaces (URL-building headers or response body)
// of resp but NOT in baseline. This is the same FP-guard the base
// detector applies, lifted to a function so the advanced probes share
// the rule.
func attackerReflected(resp, baseline *internalhttp.Response, attacker string) bool {
	if resp == nil || baseline == nil {
		return false
	}
	atk := strings.ToLower(attacker)
	for _, hdr := range []string{"Location", "Link", "Refresh", "Content-Location"} {
		if v := resp.Headers[hdr]; v != "" && strings.Contains(strings.ToLower(v), atk) {
			if !strings.Contains(strings.ToLower(baseline.Headers[hdr]), atk) {
				return true
			}
		}
	}
	body := strings.ToLower(resp.Body)
	baseBody := strings.ToLower(baseline.Body)
	if strings.Contains(body, atk) && !strings.Contains(baseBody, atk) {
		return true
	}
	return false
}

// rawHTTPRoundTrip writes a hand-built HTTP/1.1 request over a raw
// net.Conn and returns the response body. This bypass is required for
// the absolute-URI conflict probe because net/http normalizes
// absolute-URI request lines before the wire, defeating the test.
func rawHTTPRoundTrip(ctx context.Context, addr, requestLine string, headers map[string]string, timeout time.Duration) (string, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	var b strings.Builder
	b.WriteString(requestLine)
	b.WriteString("\r\n")
	for k, v := range headers {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(v)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")

	if _, err := conn.Write([]byte(b.String())); err != nil {
		return "", fmt.Errorf("write request: %w", err)
	}

	// Read the full response. We don't need to fully parse headers; we
	// just need the body text for substring matching. Split on the
	// canonical \r\n\r\n boundary.
	reader := bufio.NewReader(conn)
	var raw strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			raw.Write(buf[:n])
		}
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			// EOF and timeout are expected termination conditions for
			// Connection: close responses.
			break
		}
	}
	full := raw.String()
	if idx := strings.Index(full, "\r\n\r\n"); idx != -1 {
		return full[idx+4:], nil
	}
	return full, nil
}

// randomMarker returns a hex-encoded random token suitable as an
// X-Cache-Bust value. 8 bytes (16 hex chars) is plenty for collision
// avoidance within a single scan session.
func randomMarker() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// appendQuery returns target with the (k, v) pair appended to its query
// string. Used to scope cache-poisoning probes to a unique cache key.
func appendQuery(target, k, v string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(k, v)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// newForwardedHostFinding builds the Critical finding for a confirmed
// X-Forwarded-Host / Forwarded-driven reflection.
func newForwardedHostFinding(target, via, attacker string) *core.Finding {
	f := core.NewFinding("Host Header Cache Poisoning via X-Forwarded-Host", core.SeverityCritical)
	f.URL = target
	f.Tool = toolName
	f.Confidence = core.ConfidenceHigh
	f.Description = "The application trusts the " + via + " header when building absolute URLs in the response. " +
		"A network-adjacent attacker can poison shared caches and password-reset emails with their own domain — " +
		"a near-direct path to mass account takeover when these links are emitted in transactional flows."
	f.Evidence = fmt.Sprintf("%s carrier reflected attacker host %q into response (and not into baseline)", via, attacker)
	f.Remediation = "Build absolute URLs from a server-side allowlist of canonical hosts. Configure reverse proxies " +
		"to strip or normalize X-Forwarded-Host and Forwarded before they reach the origin, or require the origin to " +
		"validate that the forwarded host matches an approved virtual host."
	f.WithOWASPMapping(
		[]string{"WSTG-INPV-20"},
		[]string{"A05:2025"},
		[]string{"CWE-20", "CWE-444"},
	)
	return f
}

// newAbsoluteURIFinding builds the High finding for a server that
// prefers Host over the absolute-URI authority on a request line.
func newAbsoluteURIFinding(target, attacker string) *core.Finding {
	f := core.NewFinding("Absolute-URI vs Host Header Conflict", core.SeverityHigh)
	f.URL = target
	f.Tool = toolName
	f.Confidence = core.ConfidenceHigh
	f.Description = "When sent an HTTP/1.1 request whose request-line carries an absolute URI but whose Host " +
		"header points at a different authority, the server routed by the Host header. RFC 7230 §5.3.2 requires " +
		"the absolute-URI authority to take precedence. This mismatch is a known precondition for HTTP request " +
		"smuggling (CWE-444) and virtual-host confusion."
	f.Evidence = fmt.Sprintf("Probe carrying absolute-URI to legitimate authority + Host: %s leaked %q into the response body", attacker, attacker)
	f.Remediation = "Configure the origin (and any intermediaries) to prefer the request-line authority over the " +
		"Host header when both are present, or to reject the request when they disagree. Ensure proxies and origins " +
		"agree on the authoritative routing key for a given request."
	f.WithOWASPMapping(
		[]string{"WSTG-INPV-20"},
		[]string{"A02:2025"},
		[]string{"CWE-444", "CWE-20"},
	)
	return f
}

// newCachePoisoningFinding builds the Critical finding for a confirmed
// cross-client cache hit on attacker-poisoned content.
func newCachePoisoningFinding(target, attacker string) *core.Finding {
	f := core.NewFinding("Cache Poisoning via Host Header", core.SeverityCritical)
	f.URL = target
	f.Tool = toolName
	f.Confidence = core.ConfidenceConfirmed
	f.Description = "A poisoned request carrying X-Forwarded-Host was cached by an intermediary. A subsequent " +
		"unrelated request to the same cache key received the attacker-controlled content. This is the canonical " +
		"web-cache-poisoning chain: any visitor who shares the cache key now sees the attacker's host in canonical " +
		"links, password-reset URLs, and asset references."
	f.Evidence = fmt.Sprintf("Clean follow-up request (no X-Forwarded-Host) received cached body containing %q", attacker)
	f.Remediation = "Include the Host / X-Forwarded-Host / Forwarded headers in the cache key, OR strip them at " +
		"the cache edge so the origin never trusts user-controlled forwarding headers. Treat any header that " +
		"influences response content but isn't keyed by the cache as a poisoning risk."
	f.WithOWASPMapping(
		[]string{"WSTG-INPV-20"},
		[]string{"A05:2025", "A02:2025"},
		[]string{"CWE-444", "CWE-20"},
	)
	return f
}

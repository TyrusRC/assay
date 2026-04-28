package ws

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gobwas/ws/wsutil"
	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

// Detector finds WebSocket security issues. It uses the shared internal
// http.Client so proxy / custom headers / cookies / UA / insecure TLS
// settings all flow through automatically.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new WS detector.
func New(client *http.Client) *Detector {
	return &Detector{client: client}
}

// WithVerbose enables verbose stderr output.
func (d *Detector) WithVerbose(v bool) *Detector { d.verbose = v; return d }

// DetectOptions tunes the WS scan.
type DetectOptions struct {
	Timeout time.Duration
	// MaxEndpoints caps how many discovered URLs we actually probe so
	// runaway templates / common-path fanout doesn't dominate scan time.
	MaxEndpoints int
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{Timeout: 10 * time.Second, MaxEndpoints: 10}
}

// DetectionResult bundles the WS detector's findings.
type DetectionResult struct {
	Vulnerable bool
	Findings   []*core.Finding
	Tested     int
}

// Detect runs the full WS audit on a target.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.MaxEndpoints <= 0 {
		opts.MaxEndpoints = 6
	}

	result := &DetectionResult{Findings: make([]*core.Finding, 0)}

	endpoints := d.discoverEndpoints(ctx, target)
	if d.verbose {
		fmt.Fprintf(os.Stderr, "[ws] discovered %d candidate endpoints (cap=%d)\n", len(endpoints), opts.MaxEndpoints)
	}
	if len(endpoints) > opts.MaxEndpoints {
		endpoints = endpoints[:opts.MaxEndpoints]
	}

	for _, ep := range endpoints {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}
		result.Tested++

		base := d.baseDialOpts(ep, opts.Timeout)

		// Phase 1: baseline dial. If it doesn't even handshake, skip
		// further checks for this endpoint — the server isn't speaking
		// WebSocket here, so subsequent dials would just be noise.
		baseline, err := dialWS(ctx, base)
		if err != nil || baseline == nil || !baseline.upgraded {
			if d.verbose {
				status := 0
				if baseline != nil {
					status = baseline.statusCode
				}
				fmt.Fprintf(os.Stderr, "[ws]   dial %s -> no upgrade (status=%d, err=%v)\n", ep, status, err)
			}
			if baseline != nil && baseline.conn != nil {
				baseline.conn.Close()
			}
			continue
		}
		baseline.conn.Close()
		if d.verbose {
			fmt.Fprintf(os.Stderr, "[ws]   dial %s -> 101 OK, running CSWSH/auth/reflection probes\n", ep)
		}

		// Phase 2: CSWSH — re-dial with a hostile Origin while keeping the
		// session cookie. If the server still upgrades, Origin is not
		// being checked: classic CSWSH (CWE-1385).
		if f := d.checkCSWSH(ctx, base, ep); f != nil {
			result.Findings = append(result.Findings, f)
			result.Vulnerable = true
		}

		// Phase 3: missing-auth on connect — re-dial with NO cookies and
		// NO Authorization header. If the server still upgrades, the WS
		// channel is anonymous-accessible, which is a finding only when
		// the baseline shipped credentials in the first place.
		if d.client.HasAuth() {
			if f := d.checkAnonymous(ctx, base, ep); f != nil {
				result.Findings = append(result.Findings, f)
				result.Vulnerable = true
			}
		}

		// Phase 4: message reflection — send a unique sentinel; if the
		// server echoes it verbatim, this is a candidate sink for
		// XSS-via-WebSocket if the receiver renders it as HTML.
		if f := d.checkReflection(ctx, base, ep); f != nil {
			result.Findings = append(result.Findings, f)
			result.Vulnerable = true
		}
	}

	return result, nil
}

// baseDialOpts builds dial options that mirror the http.Client's per-scan
// settings (proxy/headers/cookies/UA/insecure) so every WS dial respects
// the global plumbing.
func (d *Detector) baseDialOpts(target string, timeout time.Duration) dialOpts {
	cfg := d.client.Snapshot()
	return dialOpts{
		url:       target,
		headers:   cfg.Headers,
		cookies:   cfg.Cookies,
		userAgent: cfg.UserAgent,
		origin:    inferOrigin(target),
		proxyURL:  cfg.ProxyURL,
		insecure:  cfg.Insecure,
		timeout:   timeout,
	}
}

// inferOrigin returns the natural same-origin value for the WS URL, which
// is what the baseline dial uses so we don't trigger Origin checks on the
// first probe.
func inferOrigin(wsURL string) string {
	u, err := url.Parse(wsURL)
	if err != nil {
		return ""
	}
	scheme := "https"
	if u.Scheme == "ws" {
		scheme = "http"
	}
	return scheme + "://" + u.Host
}

// checkCSWSH verifies the server enforces Origin on WS handshakes. We
// re-use the baseline opts but swap Origin for an attacker-controlled
// value. We require an upgrade AND non-empty server frame to call it
// confirmed — many servers 101 first then immediately drop unauth'd
// connections.
func (d *Detector) checkCSWSH(ctx context.Context, base dialOpts, ep string) *core.Finding {
	hostile := base
	hostile.origin = "https://evil.attacker.example"

	res, err := dialWS(ctx, hostile)
	if err != nil || res == nil || !res.upgraded {
		if res != nil && res.conn != nil {
			res.conn.Close()
		}
		return nil
	}
	defer res.conn.Close()

	// Read with a tight deadline — if the server volunteers a frame, that's
	// strong proof the connection is fully usable from the hostile origin.
	_ = res.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	frame, _ := wsutil.ReadServerText(res.conn)

	confidence := core.ConfidenceMedium
	if len(frame) > 0 {
		confidence = core.ConfidenceHigh
	}

	f := core.NewFinding("Cross-Site WebSocket Hijacking (CSWSH)", core.SeverityHigh)
	f.URL = ep
	f.Description = "WebSocket handshake accepted from an attacker-controlled Origin while the user's session cookie was sent. " +
		"Any cross-origin page can connect to this endpoint and read/write on behalf of the victim."
	f.Evidence = fmt.Sprintf("Origin: %s; upgrade=101; first-frame-bytes=%d", hostile.origin, len(frame))
	f.Tool = "ws-detector"
	f.Confidence = confidence
	f.Remediation = "Validate the Sec-WebSocket-Origin / Origin header against an allowlist before completing the handshake. " +
		"Treat WS handshakes like CSRF-protected endpoints (require a CSRF token or SameSite=Strict session cookie)."
	f.WithOWASPMapping(
		[]string{"WSTG-CLNT-10"},
		[]string{"A05:2025"},
		[]string{"CWE-1385"},
	)
	return f
}

// checkAnonymous verifies the server actually requires the credentials
// the user's session would carry. Only meaningful when the baseline used
// auth — guarded by Detector.Detect.
func (d *Detector) checkAnonymous(ctx context.Context, base dialOpts, ep string) *core.Finding {
	anon := base
	anon.cookies = ""
	// Strip Authorization if it was set globally.
	if anon.headers != nil {
		clean := make(map[string]string, len(anon.headers))
		for k, v := range anon.headers {
			if strings.EqualFold(k, "Authorization") {
				continue
			}
			clean[k] = v
		}
		anon.headers = clean
	}

	res, err := dialWS(ctx, anon)
	if err != nil || res == nil || !res.upgraded {
		if res != nil && res.conn != nil {
			res.conn.Close()
		}
		return nil
	}
	defer res.conn.Close()

	f := core.NewFinding("WebSocket Authentication Bypass (Anonymous Connect)", core.SeverityMedium)
	f.URL = ep
	f.Description = "WebSocket endpoint accepted a handshake without any session cookie or Authorization header. " +
		"If the server treats this connection as authenticated for any user-specific data, this is an authentication-bypass."
	f.Evidence = "anonymous handshake upgraded to 101"
	f.Tool = "ws-detector"
	f.Confidence = core.ConfidenceMedium
	f.Remediation = "Reject WS handshakes that lack valid authentication. Authenticate at the handshake boundary, not via the first message."
	f.WithOWASPMapping(
		[]string{"WSTG-ATHN-04"},
		[]string{"A07:2025"},
		[]string{"CWE-306"},
	)
	return f
}

// checkReflection sends a unique sentinel to the WS endpoint and looks
// for verbatim echo in the reply — a precondition for XSS-via-WS.
func (d *Detector) checkReflection(ctx context.Context, base dialOpts, ep string) *core.Finding {
	res, err := dialWS(ctx, base)
	if err != nil || res == nil || !res.upgraded {
		if res != nil && res.conn != nil {
			res.conn.Close()
		}
		return nil
	}
	defer res.conn.Close()

	sentinel := wsSentinel()
	probe := fmt.Sprintf(`{"msg":"<img src=x onerror=%s>"}`, sentinel)
	_ = res.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if err := wsutil.WriteClientText(res.conn, []byte(probe)); err != nil {
		return nil
	}
	_ = res.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reply, err := wsutil.ReadServerText(res.conn)
	if err != nil || len(reply) == 0 {
		return nil
	}
	if !strings.Contains(string(reply), sentinel) {
		return nil
	}

	f := core.NewFinding("WebSocket Message Reflection (XSS Sink Candidate)", core.SeverityMedium)
	f.URL = ep
	f.Description = "WebSocket server echoed an attacker-controlled payload verbatim, including HTML/JS markup. " +
		"If the receiving page renders this message as HTML (e.g. innerHTML), this is XSS over WebSocket."
	f.Evidence = fmt.Sprintf("sentinel %q reflected; payload=%s", sentinel, probe)
	f.Tool = "ws-detector"
	f.Confidence = core.ConfidenceMedium
	f.Remediation = "Treat WebSocket messages as untrusted; encode for the receiving sink (textContent, not innerHTML)."
	f.WithOWASPMapping(
		[]string{"WSTG-INPV-01"},
		[]string{"A03:2025"},
		[]string{"CWE-79"},
	)
	return f
}

// wsSentinel returns a short hex string unlikely to appear by accident.
func wsSentinel() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "skwsws_" + hex.EncodeToString(b)
}

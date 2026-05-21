package http2desync

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

// Detector probes a target for CL.0 desync and h2c upgrade
// vulnerabilities. Uses raw TCP rather than an HTTP client because
// net/http normalizes the header forms these attacks depend on.
type Detector struct {
	verbose bool
}

// New constructs a Detector.
func New() *Detector { return &Detector{} }

// WithVerbose toggles diagnostic output.
func (d *Detector) WithVerbose(v bool) *Detector {
	d.verbose = v
	return d
}

// Name returns the detector identifier.
func (d *Detector) Name() string { return "http2desync" }

// Description returns a one-line summary.
func (d *Detector) Description() string {
	return "Probes for CL.0 desync (Content-Length: 0 + smuggled body) and h2c upgrade acceptance — desync vectors not covered by smuggling/ (CL.TE/TE.CL/TE.TE) or http2advanced/."
}

// DetectOptions configures the probe.
type DetectOptions struct {
	// CL0Threshold is the response-time gap above which the CL.0
	// timing test is considered to have detected a desynced backend.
	// 400ms is a conservative default that beats normal proxy jitter
	// while still firing on the typical 1-2s stall a CL.0-vulnerable
	// backend exhibits.
	CL0Threshold time.Duration
	// ProbeTimeout is the per-probe TCP timeout.
	ProbeTimeout time.Duration
}

// DefaultOptions returns recommended defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		CL0Threshold: 400 * time.Millisecond,
		ProbeTimeout: 5 * time.Second,
	}
}

// DetectionResult carries findings and the list of techniques that
// triggered.
type DetectionResult struct {
	Vulnerable bool
	Findings   []*core.Finding
	Techniques []string
}

// Detect runs the two probes against target. Each probe is
// independent; a failure in one does not abort the other.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	res := &DetectionResult{
		Findings:   make([]*core.Finding, 0),
		Techniques: make([]string, 0),
	}
	if opts.CL0Threshold == 0 {
		opts.CL0Threshold = DefaultOptions().CL0Threshold
	}
	if opts.ProbeTimeout == 0 {
		opts.ProbeTimeout = DefaultOptions().ProbeTimeout
	}

	hostPort, path, err := splitTarget(target)
	if err != nil {
		return res, fmt.Errorf("http2desync: %w", err)
	}

	if d.probeCL0(ctx, hostPort, path, opts) {
		res.Techniques = append(res.Techniques, "cl0_desync")
		res.Findings = append(res.Findings, buildCL0Finding(target))
	}

	if d.probeH2cUpgrade(ctx, hostPort, path, opts) {
		res.Techniques = append(res.Techniques, "h2c_upgrade")
		res.Findings = append(res.Findings, buildH2cFinding(target))
	}

	res.Vulnerable = len(res.Findings) > 0
	return res, nil
}

// splitTarget extracts host:port and path from a URL. Defaults to
// :80 / :443 based on scheme when no port is present.
func splitTarget(target string) (hostPort, path string, err error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", "", err
	}
	host := u.Hostname()
	if host == "" {
		return "", "", fmt.Errorf("missing host in %q", target)
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	path = u.Path
	if path == "" {
		path = "/"
	}
	return host + ":" + port, path, nil
}

// probeCL0 sends two requests on separate connections — a clean POST
// baseline and a CL.0 + body desync attempt — and reports a hit when
// the CL.0 attempt takes meaningfully longer.
func (d *Detector) probeCL0(ctx context.Context, hostPort, path string, opts DetectOptions) bool {
	host := hostHeaderFor(hostPort)

	baselineReq := strings.Join([]string{
		"POST " + path + " HTTP/1.1",
		"Host: " + host,
		"Content-Length: 1",
		"Connection: close",
		"",
		"x",
	}, "\r\n")
	baseline, err := timedSend(ctx, hostPort, baselineReq, opts.ProbeTimeout)
	if err != nil {
		return false
	}

	// CL.0 desync payload: Content-Length: 0 advertised, but the body
	// contains a complete second request. A vulnerable backend reads
	// the body anyway and stalls waiting for the rest of the smuggled
	// request's headers.
	smuggled := strings.Join([]string{
		"GET /smuggled HTTP/1.1",
		"Host: " + host,
		"X-Smuggle: 1",
		"",
		"",
	}, "\r\n")
	desyncReq := strings.Join([]string{
		"POST " + path + " HTTP/1.1",
		"Host: " + host,
		"Content-Length: 0",
		"Connection: close",
		"",
		"",
	}, "\r\n") + smuggled
	desync, err := timedSend(ctx, hostPort, desyncReq, opts.ProbeTimeout)
	if err != nil {
		return false
	}

	delta := desync - baseline
	return delta >= opts.CL0Threshold
}

// probeH2cUpgrade sends an HTTP/1.1 GET with the Upgrade: h2c headers
// and checks for a 101 Switching Protocols response.
func (d *Detector) probeH2cUpgrade(ctx context.Context, hostPort, path string, opts DetectOptions) bool {
	host := hostHeaderFor(hostPort)
	req := strings.Join([]string{
		"GET " + path + " HTTP/1.1",
		"Host: " + host,
		"Connection: Upgrade, HTTP2-Settings",
		"Upgrade: h2c",
		"HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA",
		"",
		"",
	}, "\r\n")
	body, _, err := rawSend(ctx, hostPort, req, opts.ProbeTimeout)
	if err != nil {
		return false
	}
	return strings.HasPrefix(body, "HTTP/1.1 101") ||
		strings.Contains(body, "101 Switching Protocols")
}

func hostHeaderFor(hostPort string) string {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	// Standard ports are omitted from the Host header per RFC 7230.
	if port == "80" || port == "443" {
		return host
	}
	return hostPort
}

// timedSend returns the round-trip duration of a single request.
func timedSend(ctx context.Context, hostPort, req string, timeout time.Duration) (time.Duration, error) {
	_, dur, err := rawSend(ctx, hostPort, req, timeout)
	return dur, err
}

// rawSend opens a TCP connection, writes req, reads until EOF or
// timeout, and returns the response body and elapsed time.
func rawSend(ctx context.Context, hostPort, req string, timeout time.Duration) (string, time.Duration, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		return "", 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	start := time.Now()
	if _, err := conn.Write([]byte(req)); err != nil {
		return "", 0, err
	}
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return sb.String(), time.Since(start), nil
}

func buildCL0Finding(target string) *core.Finding {
	f := core.NewFinding("HTTP request smuggling: CL.0 desync", core.SeverityCritical)
	f.Title = "CL.0 desync — backend reads body despite Content-Length: 0"
	f.URL = target
	f.Tool = "http2desync-detector"
	f.Description = "A request with Content-Length: 0 and a body containing a smuggled GET / request triggered a significant response delay compared to a clean baseline. The frontend honored the zero-length declaration and forwarded an empty body, but the backend kept reading the socket and treated the smuggled bytes as the start of the next request — stalling while waiting for the rest of those headers. An attacker can hijack subsequent users' requests on the shared backend connection."
	f.Evidence = "CL.0 + smuggled-body request took CL0Threshold longer than a clean baseline — backend is reading the body the frontend said wasn't there."
	f.Remediation = "Configure the frontend proxy to drop or reject Content-Length: 0 requests that carry a body, or strip body bytes after CL bytes have been read. Where possible, enforce HTTP/2 end-to-end (no h1 backhop) so framing comes from frame headers rather than parsed CL values."
	f.WithOWASPMapping(
		[]string{"WSTG-INPV-15"},
		[]string{"A05:2025"},
		[]string{"CWE-444"},
	)
	return f
}

func buildH2cFinding(target string) *core.Finding {
	f := core.NewFinding("HTTP/2 cleartext (h2c) upgrade accepted", core.SeverityMedium)
	f.Title = "h2c upgrade accepted — cleartext HTTP/2 prior-knowledge enabled"
	f.URL = target
	f.Tool = "http2desync-detector"
	f.Description = "The server responded 101 Switching Protocols to an HTTP/1.1 request carrying Upgrade: h2c. Cleartext HTTP/2 is rarely safe in production: when a frontend honors the upgrade but routes the resulting connection to an h1 backend, subsequent bytes are interpreted as HTTP/1.1 requests and can be smuggled past frontend ACLs. Even when the upgrade terminates at the frontend, h2c is almost always a misconfiguration."
	f.Evidence = "GET / + Upgrade: h2c returned 101 Switching Protocols"
	f.Remediation = "Disable Upgrade: h2c at the frontend (refuse the Upgrade header). If HTTP/2 is required between hops, run HTTP/2 over TLS (h2) end-to-end and refuse cleartext upgrade."
	f.WithOWASPMapping(
		[]string{"WSTG-CONF-12"},
		[]string{"A05:2025"},
		[]string{"CWE-444"},
	)
	return f
}

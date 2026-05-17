package http2advanced

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
)

// defaultTimeout is applied when DetectOptions.Timeout is zero. Each probe
// is capped independently so a single misbehaving target cannot stall the
// caller.
const defaultTimeout = 5 * time.Second

// settingsFloodCount is the number of SETTINGS frames we emit during the
// flood probe. >100 in <1s is the abuse threshold cited in the spec; we
// send 150 to leave headroom for slow loopback servers.
const settingsFloodCount = 150

// settingsFloodWindow is the upper bound on how long the flood may take
// before we consider the server "rate-limited" by virtue of slowing the
// channel down (i.e. defensive backpressure).
const settingsFloodWindow = 1 * time.Second

// flowControlStreamCount is how many streams the flow-control probe opens
// without consuming DATA. 64 is enough to exhaust the default 64KB
// per-stream window many times over.
const flowControlStreamCount = 64

// toolName is the canonical Tool tag attached to every finding emitted by
// this package; tests and downstream aggregators key off it.
const toolName = "http2advanced-detector"

// DetectOptions configures a single probe invocation.
type DetectOptions struct {
	// Target overrides Detector.Target if non-empty. Both forms are
	// accepted because callers sometimes construct a Detector once and
	// re-target per-call.
	Target string
	// AllowDestructive must be explicitly enabled for probes that can
	// degrade the target (currently only DetectFlowControlExhaustion).
	AllowDestructive bool
	// Timeout caps the total wall-clock time spent on a single probe.
	// Zero falls back to defaultTimeout.
	Timeout time.Duration
}

// DetectionResult is the per-probe return value. Findings is empty when
// Vulnerable is false; the inverse is enforced by tests.
type DetectionResult struct {
	Vulnerable    bool
	Findings      []*core.Finding
	DetectionType string
}

// Detector probes an HTTP/2 target for frame-level abuses. The zero value
// is not useful; construct via New.
type Detector struct {
	// Target is the canonical https URL of the host under test.
	Target string
	// InsecureSkipVerify is propagated to the TLS dialer. Tests against
	// httptest.NewTLSServer require this; scanners typically pass
	// --insecure on real targets.
	InsecureSkipVerify bool
}

// New returns a Detector bound to target.
func New(target string) *Detector {
	return &Detector{Target: target}
}

// tlsConfig returns the TLS config used for the H/2 ALPN dial. Extracted
// so tests can assert the negotiated NextProtos contains "h2".
func (d *Detector) tlsConfig(serverName string) *tls.Config {
	return &tls.Config{
		ServerName:         serverName,
		NextProtos:         []string{"h2"},
		InsecureSkipVerify: d.InsecureSkipVerify, //nolint:gosec // by design, opt-in via Detector field
		MinVersion:         tls.VersionTLS12,
	}
}

// resolveTarget normalises whichever target the caller passed (opts wins
// over d.Target) into a *url.URL plus host:port string. Returns ok=false
// for non-https / unparseable inputs, which the caller treats as a no-op.
func (d *Detector) resolveTarget(opts DetectOptions) (*url.URL, string, bool) {
	raw := opts.Target
	if raw == "" {
		raw = d.Target
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Scheme != "https" || u.Host == "" {
		return nil, "", false
	}
	host := u.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = u.Host + ":443"
	}
	return u, host, true
}

// dialH2 establishes a TLS connection and negotiates ALPN "h2". Returns
// (conn, ok). ok=false swallows the error and lets the caller no-op —
// network failures must never bubble up as detection findings.
func (d *Detector) dialH2(ctx context.Context, u *url.URL, host string) (*tls.Conn, bool) {
	dialer := &tls.Dialer{Config: d.tlsConfig(u.Hostname())}
	raw, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, false
	}
	tlsConn, ok := raw.(*tls.Conn)
	if !ok {
		_ = raw.Close()
		return nil, false
	}
	if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		_ = tlsConn.Close()
		return nil, false
	}
	return tlsConn, true
}

// sendPrefaceAndSettings writes the H/2 client preface + an initial
// (empty) SETTINGS frame, then drains the server's first SETTINGS so the
// framer is positioned for whatever the probe wants to do next.
func sendPrefaceAndSettings(conn net.Conn, framer *http2.Framer) bool {
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		return false
	}
	if err := framer.WriteSettings(); err != nil {
		return false
	}
	// Drain a few frames until we see the server's SETTINGS. We don't
	// care about specific values for the SETTINGS-flood probe.
	for i := 0; i < 4; i++ {
		f, err := framer.ReadFrame()
		if err != nil {
			return false
		}
		if _, ok := f.(*http2.SettingsFrame); ok {
			// ACK and proceed.
			if err := framer.WriteSettingsAck(); err != nil {
				return false
			}
			return true
		}
	}
	return false
}

// h2Session bundles the artefacts produced by openH2Session so callers
// can drive a probe over a ready-to-use framer.
type h2Session struct {
	conn   *tls.Conn
	framer *http2.Framer
	u      *url.URL
	host   string
	cancel context.CancelFunc
}

// close releases the dial-context and tears down the conn. Safe to call
// multiple times.
func (s *h2Session) close() {
	if s == nil {
		return
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
	if s.cancel != nil {
		s.cancel()
	}
}

// openH2Session resolves the target, dials TLS+ALPN(h2), sends the H/2
// preface and initial SETTINGS, and primes a framer. Returns (nil, false)
// on any failure path; callers no-op in that case.
func (d *Detector) openH2Session(ctx context.Context, opts DetectOptions) (*h2Session, bool) {
	u, host, ok := d.resolveTarget(opts)
	if !ok {
		return nil, false
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)

	conn, ok := d.dialH2(dialCtx, u, host)
	if !ok {
		cancel()
		return nil, false
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	framer := http2.NewFramer(conn, conn)
	if !sendPrefaceAndSettings(conn, framer) {
		_ = conn.Close()
		cancel()
		return nil, false
	}
	return &h2Session{conn: conn, framer: framer, u: u, host: host, cancel: cancel}, true
}

// writeOversizeSettings emits a single SETTINGS frame stuffed with 1024
// repeated parameters. Returns false if the server cut us off mid-write
// (defensive behaviour — caller should no-op).
func writeOversizeSettings(framer *http2.Framer) bool {
	oversize := make([]http2.Setting, 0, 1024)
	for i := 0; i < 1024; i++ {
		oversize = append(oversize, http2.Setting{
			ID:  http2.SettingHeaderTableSize,
			Val: uint32(i),
		})
	}
	return framer.WriteSettings(oversize...) == nil
}

// floodSettings emits up to settingsFloodCount small SETTINGS frames as
// fast as the framer will accept them and returns (accepted, elapsed).
func floodSettings(framer *http2.Framer) (int, time.Duration) {
	start := time.Now()
	accepted := 0
	for i := 0; i < settingsFloodCount; i++ {
		if err := framer.WriteSettings(http2.Setting{
			ID:  http2.SettingInitialWindowSize,
			Val: uint32(65535 + i),
		}); err != nil {
			break
		}
		accepted++
	}
	return accepted, time.Since(start)
}

// DetectSettingsFlood emits a burst of SETTINGS frames (including one
// with an oversize parameter list) and decides whether the server applied
// any backpressure. A server that accepts the full burst within
// settingsFloodWindow without GOAWAY/RST is flagged.
func (d *Detector) DetectSettingsFlood(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	res := &DetectionResult{DetectionType: "settings-flood"}

	sess, ok := d.openH2Session(ctx, opts)
	if !ok {
		return res, nil
	}
	defer sess.close()

	if !writeOversizeSettings(sess.framer) {
		return res, nil
	}
	accepted, elapsed := floodSettings(sess.framer)

	if pollForPushbackFlood(sess.framer, 250*time.Millisecond) {
		return res, nil
	}
	if accepted < 100 || elapsed > settingsFloodWindow {
		// Implicit backpressure — server slowed or refused mid-burst.
		return res, nil
	}

	res.Vulnerable = true
	res.Findings = append(res.Findings, buildSettingsFloodFinding(sess.u.String(), sess.host, accepted, elapsed))
	return res, nil
}

// writeRequestHeaders is a convenience wrapper that writes a single
// HEADERS frame for streamID with END_STREAM+END_HEADERS set.
func writeRequestHeaders(framer *http2.Framer, streamID uint32, block []byte) error {
	return framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: block,
		EndStream:     true,
		EndHeaders:    true,
	})
}

// DetectHPACKPollution opens stream 1 with a probe header (added to the
// HPACK dynamic table), then opens stream 3 with NO x-test header. If the
// stream-3 response surfaces the stream-1 probe value (in headers, the
// :status pseudo-header, or echoed via a custom header the handler set),
// the server is leaking HPACK state across streams.
func (d *Detector) DetectHPACKPollution(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	res := &DetectionResult{DetectionType: "hpack-pollution"}

	sess, ok := d.openH2Session(ctx, opts)
	if !ok {
		return res, nil
	}
	defer sess.close()

	const probeMarker = "skws-hpack-probe-marker-3f9e2c1a"

	// Stream 1: GET with x-test: probeMarker → adds the entry to the
	// HPACK dynamic table.
	hdr1 := encodeHeaders(sess.u, []hpack.HeaderField{{Name: "x-test", Value: probeMarker}})
	if err := writeRequestHeaders(sess.framer, 1, hdr1); err != nil {
		return res, nil
	}
	// Stream 3: GET with NO x-test. A correct decoder emits no x-test.
	if err := writeRequestHeaders(sess.framer, 3, encodeHeaders(sess.u, nil)); err != nil {
		return res, nil
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	headersByStream := readResponseHeaders(sess.framer, time.Now().Add(timeout))
	for _, hf := range headersByStream[3] {
		if strings.Contains(strings.ToLower(hf.Value), probeMarker) {
			res.Vulnerable = true
			res.Findings = append(res.Findings, buildHPACKPollutionFinding(sess.u.String(), sess.host, probeMarker, hf))
			return res, nil
		}
	}
	return res, nil
}

// openManyStallableStreams shrinks the initial window to 1 byte then
// opens up to flowControlStreamCount streams without ever sending
// WINDOW_UPDATE. Returns the count actually opened.
func openManyStallableStreams(framer *http2.Framer, u *url.URL) int {
	if err := framer.WriteSettings(http2.Setting{
		ID:  http2.SettingInitialWindowSize,
		Val: 1,
	}); err != nil {
		return 0
	}
	hdr := encodeHeaders(u, nil)
	streamID := uint32(1)
	opened := 0
	for i := 0; i < flowControlStreamCount; i++ {
		if err := writeRequestHeaders(framer, streamID, hdr); err != nil {
			break
		}
		opened++
		streamID += 2
	}
	return opened
}

// DetectFlowControlExhaustion is gated behind opts.AllowDestructive. When
// enabled it opens flowControlStreamCount streams without sending
// WINDOW_UPDATEs, then watches for a server that stalls every stream past
// the initial 1-byte credit — the canonical flow-control DoS pattern.
func (d *Detector) DetectFlowControlExhaustion(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	res := &DetectionResult{DetectionType: "flowcontrol-exhaustion"}

	if !opts.AllowDestructive {
		// Safety contract: never run a destructive probe implicitly.
		return res, nil
	}

	sess, ok := d.openH2Session(ctx, opts)
	if !ok {
		return res, nil
	}
	defer sess.close()

	opened := openManyStallableStreams(sess.framer, sess.u)
	if opened == 0 {
		return res, nil
	}

	// Watch for pushback. A protected server will GOAWAY, RST_STREAM
	// with FLOW_CONTROL_ERROR, or close the connection. A vulnerable
	// server just stalls — we observe by checking whether ANY DATA
	// arrives within a short window. Note: a 1-byte initial window
	// means even a "Hello" body cannot arrive without WINDOW_UPDATE.
	stalled, gotPushback := observeFlowControlBehaviour(sess.framer, 500*time.Millisecond)

	if gotPushback || !stalled {
		// Server pushed back OR delivered data anyway — not vulnerable
		// to this exact pattern.
		return res, nil
	}

	res.Vulnerable = true
	res.Findings = append(res.Findings, buildFlowControlFinding(sess.u.String(), sess.host, opened))
	return res, nil
}

// DetectAll runs each probe in sequence and aggregates the findings.
// Errors are swallowed per-probe (each probe already swallows network
// failures) so DetectAll never returns a non-nil error today; the
// signature reserves the right to.
func (d *Detector) DetectAll(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	all := &DetectionResult{DetectionType: "all"}

	if r, err := d.DetectSettingsFlood(ctx, opts); err == nil && r != nil {
		all.Findings = append(all.Findings, r.Findings...)
	}
	if r, err := d.DetectHPACKPollution(ctx, opts); err == nil && r != nil {
		all.Findings = append(all.Findings, r.Findings...)
	}
	if r, err := d.DetectFlowControlExhaustion(ctx, opts); err == nil && r != nil {
		all.Findings = append(all.Findings, r.Findings...)
	}

	all.Vulnerable = len(all.Findings) > 0
	return all, nil
}

// pollForPushbackFlood watches for GOAWAY, ENHANCE_YOUR_CALM, or a
// connection close within deadline. true = server pushed back.
func pollForPushbackFlood(framer *http2.Framer, deadline time.Duration) bool {
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		f, err := framer.ReadFrame()
		if err != nil {
			// Connection closed counts as pushback.
			return true
		}
		switch ft := f.(type) {
		case *http2.GoAwayFrame:
			return true
		case *http2.RSTStreamFrame:
			if ft.ErrCode == http2.ErrCodeEnhanceYourCalm {
				return true
			}
		}
	}
	return false
}

// readResponseHeaders pumps frames until either:
//   - deadline elapses,
//   - the framer returns an error (connection closed / framer broken),
//   - we have a HEADERS frame for every expected stream and END_STREAM is
//     observed (we settle for "at least one HEADERS per stream" because
//     the server may keep sending DATA frames we don't care about).
//
// Returned map is keyed by stream ID -> the decoded header fields of the
// first HEADERS frame seen on that stream.
func readResponseHeaders(framer *http2.Framer, end time.Time) map[uint32][]hpack.HeaderField {
	out := make(map[uint32][]hpack.HeaderField)
	dec := hpack.NewDecoder(4096, nil)
	for time.Now().Before(end) {
		f, err := framer.ReadFrame()
		if err != nil {
			return out
		}
		hf, ok := f.(*http2.HeadersFrame)
		if !ok {
			continue
		}
		fields, derr := dec.DecodeFull(hf.HeaderBlockFragment())
		if derr != nil {
			continue
		}
		if _, seen := out[hf.StreamID]; !seen {
			out[hf.StreamID] = fields
		}
		// Stop once we've seen at least two streams (1 and 3 in the
		// HPACK probe).
		if len(out) >= 2 {
			return out
		}
	}
	return out
}

// observeFlowControlBehaviour returns (stalled, gotPushback):
//   - stalled=true means we saw NO DATA frames in the window.
//   - gotPushback=true means we saw GOAWAY or RST_STREAM(FLOW_CONTROL_ERROR).
//
// A protected server should produce gotPushback=true OR deliver responses
// out of band (stalled=false). A vulnerable server produces stalled=true,
// gotPushback=false.
func observeFlowControlBehaviour(framer *http2.Framer, window time.Duration) (bool, bool) {
	end := time.Now().Add(window)
	gotData := false
	for time.Now().Before(end) {
		f, err := framer.ReadFrame()
		if err != nil {
			// Connection close = pushback in this context.
			return !gotData, true
		}
		switch ft := f.(type) {
		case *http2.GoAwayFrame:
			return !gotData, true
		case *http2.RSTStreamFrame:
			if ft.ErrCode == http2.ErrCodeFlowControl ||
				ft.ErrCode == http2.ErrCodeEnhanceYourCalm {
				return !gotData, true
			}
		case *http2.DataFrame:
			if len(ft.Data()) > 0 {
				gotData = true
			}
		}
	}
	return !gotData, false
}

// encodeHeaders builds an HPACK-encoded request header block for u, with
// `extra` appended after the pseudo-headers.
func encodeHeaders(u *url.URL, extra []hpack.HeaderField) []byte {
	var buf []byte
	enc := hpack.NewEncoder(&sliceWriter{p: &buf})
	path := u.Path
	if path == "" {
		path = "/"
	}
	_ = enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: u.Scheme})
	_ = enc.WriteField(hpack.HeaderField{Name: ":authority", Value: u.Host})
	_ = enc.WriteField(hpack.HeaderField{Name: ":path", Value: path})
	_ = enc.WriteField(hpack.HeaderField{Name: "user-agent", Value: "skws-http2advanced/1"})
	for _, f := range extra {
		_ = enc.WriteField(f)
	}
	return buf
}

type sliceWriter struct{ p *[]byte }

func (w *sliceWriter) Write(b []byte) (int, error) {
	*w.p = append(*w.p, b...)
	return len(b), nil
}

// buildSettingsFloodFinding assembles the High-severity finding for an
// unrate-limited SETTINGS flood.
func buildSettingsFloodFinding(target, host string, accepted int, elapsed time.Duration) *core.Finding {
	f := core.NewFinding("HTTP/2 SETTINGS Frame Flood (Unrate-Limited)", core.SeverityHigh)
	f.URL = target
	f.Tool = toolName
	f.Confidence = core.ConfidenceMedium
	f.Description = fmt.Sprintf(
		"The server accepted %d SETTINGS frames (including one oversize SETTINGS frame with 1024 parameters) within %s without sending GOAWAY, ENHANCE_YOUR_CALM, or closing the connection. An attacker can leverage this to consume server CPU on SETTINGS parsing/ACK bookkeeping or to crash stacks that mishandle oversize parameter lists.",
		accepted, elapsed.Round(time.Millisecond),
	)
	f.Evidence = fmt.Sprintf("Host: %s\nALPN: h2 (negotiated)\nSETTINGS frames accepted: %d in %s\nOversize SETTINGS frame: 1024 parameters (accepted)\nObserved pushback: none",
		host, accepted, elapsed.Round(time.Millisecond))
	f.Remediation = "Apply per-connection rate-limiting on inbound SETTINGS frames; reject SETTINGS frames whose parameter count exceeds a small bound (e.g. 8) with PROTOCOL_ERROR; ensure runtime is patched (Go 1.21.3+, nginx 1.25.3+, Envoy 1.28+). Configure SETTINGS_MAX_HEADER_LIST_SIZE and back the SETTINGS parser with a frame-frequency limiter."
	f.WithOWASPMapping(
		[]string{"WSTG-BUSL-04"},
		[]string{"A05:2025"},
		[]string{"CWE-400", "CWE-770"},
	)
	f.APITop10 = []string{"API4:2023"}
	return f
}

// buildHPACKPollutionFinding builds the Critical-severity finding for
// cross-stream HPACK dynamic-table leakage.
func buildHPACKPollutionFinding(target, host, marker string, leaked hpack.HeaderField) *core.Finding {
	f := core.NewFinding("HTTP/2 HPACK Cross-Stream Pollution", core.SeverityCritical)
	f.URL = target
	f.Tool = toolName
	f.Confidence = core.ConfidenceHigh
	f.Description = fmt.Sprintf(
		"A header value set only on stream 1 (x-test=%s) was observed in the response headers of stream 3, which never carried that header. This indicates the server's HPACK decoder is leaking dynamic-table state across streams — a critical isolation failure that can leak headers (including Authorization, Cookie) between concurrent requests on the same H/2 connection.",
		marker,
	)
	f.Evidence = fmt.Sprintf("Host: %s\nALPN: h2\nProbe marker (set on stream 1 only): %s\nLeaked header on stream 3: %s=%s",
		host, marker, leaked.Name, leaked.Value)
	f.Remediation = "Upgrade the HTTP/2 stack to a version that maintains per-stream HPACK decoder state (or, more precisely, applies the dynamic-table mutations from each HEADERS block atomically against a single connection-shared table without re-emitting prior entries on new streams). Audit the request pipeline for any code path that caches decoded HeaderFields between streams."
	f.WithOWASPMapping(
		[]string{"WSTG-INPV-12"},
		[]string{"A05:2025"},
		[]string{"CWE-400", "CWE-770"},
	)
	f.APITop10 = []string{"API8:2023"}
	return f
}

// buildFlowControlFinding builds the High-severity finding for a server
// that stalls under low-window stream multiplexing.
func buildFlowControlFinding(target, host string, opened int) *core.Finding {
	f := core.NewFinding("HTTP/2 Flow-Control Window Exhaustion", core.SeverityHigh)
	f.URL = target
	f.Tool = toolName
	f.Confidence = core.ConfidenceMedium
	f.Description = fmt.Sprintf(
		"After advertising a 1-byte SETTINGS_INITIAL_WINDOW_SIZE and opening %d streams without consuming any DATA, the server delivered no DATA frames and did not RST/GOAWAY the connection within the observation window. A malicious client can hold per-connection flow-control capacity hostage indefinitely, denying service to other consumers of the connection (and, on shared front-ends, to other tenants).",
		opened,
	)
	f.Evidence = fmt.Sprintf("Host: %s\nALPN: h2\nSETTINGS_INITIAL_WINDOW_SIZE advertised: 1 byte\nStreams opened (no WINDOW_UPDATE issued): %d\nDATA frames observed in 500ms: 0\nGOAWAY / FLOW_CONTROL_ERROR observed: no",
		host, opened)
	f.Remediation = "Enforce a per-connection idle-stream timer that resets stalled streams with FLOW_CONTROL_ERROR; cap SETTINGS_MAX_CONCURRENT_STREAMS; refuse SETTINGS frames that drop INITIAL_WINDOW_SIZE below a reasonable floor (1KB+); apply runtime patches for known H/2 flow-control DoS bugs (CVE-2023-44487 family fixes typically address related vectors)."
	f.WithOWASPMapping(
		[]string{"WSTG-BUSL-04"},
		[]string{"A05:2025"},
		[]string{"CWE-400", "CWE-770"},
	)
	f.APITop10 = []string{"API4:2023"}
	return f
}

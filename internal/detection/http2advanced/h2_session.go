package http2advanced

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

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
	_ = enc.WriteField(hpack.HeaderField{Name: "user-agent", Value: "assay-http2advanced/1"})
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

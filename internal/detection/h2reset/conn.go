package h2reset

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	"golang.org/x/net/http2"
)

// toolName labels findings produced by this package's low-level H/2 probes.
const toolName = "h2reset"

// h2conn bundles a negotiated HTTP/2 connection with its framer and parsed URL.
type h2conn struct {
	tls    *tls.Conn
	framer *http2.Framer
	u      *url.URL
}

// close releases the underlying TLS connection.
func (c *h2conn) close() {
	if c.tls != nil {
		_ = c.tls.Close()
	}
}

// dialH2 establishes a TLS+ALPN HTTP/2 connection to targetURL and writes the
// client preface and initial SETTINGS. It returns (nil, nil) when the target is
// not HTTPS or HTTP/2 is unavailable — the shared "no-op, no finding" path for
// the low-level H/2 probes. insecure mirrors the suite-wide --insecure flag.
func dialH2(ctx context.Context, targetURL string, insecure bool, timeout time.Duration) (*h2conn, error) {
	u, err := url.Parse(targetURL)
	if err != nil || u.Scheme != "https" {
		return nil, nil //nolint:nilnil // sentinel: nothing to probe, not an error
	}

	host := u.Host
	if _, _, serr := net.SplitHostPort(host); serr != nil {
		host = u.Host + ":443"
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &tls.Dialer{
		Config: &tls.Config{
			ServerName:         u.Hostname(),
			NextProtos:         []string{"h2"},
			InsecureSkipVerify: insecure, //nolint:gosec // operator opt-in via --insecure
			MinVersion:         tls.VersionTLS12,
		},
	}
	rawConn, err := dialer.DialContext(dialCtx, "tcp", host)
	if err != nil {
		return nil, nil //nolint:nilnil // unreachable target: no finding
	}

	tlsConn, ok := rawConn.(*tls.Conn)
	if !ok || tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		_ = rawConn.Close()
		return nil, nil //nolint:nilnil // no h2: no finding
	}

	if _, err := tlsConn.Write([]byte(http2.ClientPreface)); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("write preface: %w", err)
	}
	framer := http2.NewFramer(tlsConn, tlsConn)
	if err := framer.WriteSettings(); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("write settings: %w", err)
	}
	return &h2conn{tls: tlsConn, framer: framer, u: u}, nil
}

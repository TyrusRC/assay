// Package ws provides detection for WebSocket security issues:
// CSWSH (Origin enforcement), missing authentication on handshake,
// and message reflection that could enable XSS via the WS channel.
//
// Every dial honors the global proxy/headers/cookies/UA/insecure plumbing
// the rest of the scanner uses, so all WebSocket traffic shows up in
// Burp Suite's WebSocket history when --proxy is set.
package ws

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/gobwas/ws"
)

// dialOpts captures everything a single WS dial needs. Pulled out of the
// Detector struct so tests and the per-attempt logic can override fields
// (e.g. swap Origin) without mutating the detector itself.
type dialOpts struct {
	url       string
	headers   map[string]string
	cookies   string
	userAgent string
	origin    string
	proxyURL  string
	insecure  bool
	timeout   time.Duration
}

// dialResult is the minimal outcome we care about: did the upgrade
// succeed (101 Switching Protocols), and what extra signal did the
// server volunteer (e.g. a frame echoed before we sent anything).
type dialResult struct {
	conn         net.Conn
	upgraded     bool
	statusCode   int
	responseBody string
}

// dialWS performs a WebSocket handshake honoring the per-scan plumbing.
// Returns a result whose conn the caller MUST close. On error the conn is nil.
func dialWS(ctx context.Context, opts dialOpts) (*dialResult, error) {
	if opts.timeout <= 0 {
		opts.timeout = 10 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, opts.timeout)
	defer cancel()

	headers := mergeHeaders(opts)

	dialer := ws.Dialer{
		Header:  ws.HandshakeHeaderHTTP(headers),
		Timeout: opts.timeout,
	}

	if opts.proxyURL != "" {
		dialer.NetDial = makeProxyDialer(opts.proxyURL, opts.timeout)
	}

	// gobwas/ws relies on dialer.TLSConfig for wss when wrapping the dialed
	// conn itself. When we're tunneling through a CONNECT proxy we still
	// need TLS on top of the proxy-tunneled TCP stream, so we always set
	// TLSConfig and let gobwas drive the handshake.
	if strings.HasPrefix(opts.url, "wss://") {
		dialer.TLSConfig = &tls.Config{InsecureSkipVerify: opts.insecure}
	}

	result := &dialResult{}
	conn, _, hs, err := dialer.Dial(dialCtx, opts.url)
	if err != nil {
		// gobwas distinguishes handshake errors (StatusError) from network
		// errors. A handshake error still tells us something useful — the
		// server replied with HTTP and rejected — so we surface that status.
		var sErr ws.StatusError
		if errAs(err, &sErr) {
			result.statusCode = int(sErr)
			return result, nil
		}
		return nil, err
	}
	result.upgraded = true
	result.statusCode = 101
	result.conn = conn
	_ = hs // we only need the handshake to have succeeded

	return result, nil
}

// mergeHeaders flattens the per-call header inputs into a single
// http.Header-style map[string][]string while preserving the typical
// browser-style Origin/User-Agent/Cookie precedence rules.
func mergeHeaders(opts dialOpts) map[string][]string {
	h := make(map[string][]string)
	for k, v := range opts.headers {
		h[k] = []string{v}
	}
	if opts.userAgent != "" {
		h["User-Agent"] = []string{opts.userAgent}
	}
	if opts.cookies != "" {
		h["Cookie"] = []string{opts.cookies}
	}
	if opts.origin != "" {
		h["Origin"] = []string{opts.origin}
	}
	return h
}

// makeProxyDialer returns a NetDial function that tunnels TCP through an
// HTTP CONNECT proxy. Mirrors the executor's logic so all WS traffic
// lands in Burp's WS history.
func makeProxyDialer(proxyURL string, timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		u, err := url.Parse(proxyURL)
		if err != nil {
			d := &net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, addr)
		}
		proxyAddr := u.Host
		if !strings.Contains(proxyAddr, ":") {
			proxyAddr += ":8080"
		}
		d := &net.Dialer{Timeout: timeout}
		c, err := d.DialContext(ctx, "tcp", proxyAddr)
		if err != nil {
			return nil, fmt.Errorf("proxy dial: %w", err)
		}
		req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
		if _, err := c.Write([]byte(req)); err != nil {
			c.Close()
			return nil, err
		}
		buf := make([]byte, 1024)
		n, err := c.Read(buf)
		if err != nil {
			c.Close()
			return nil, err
		}
		if !strings.Contains(string(buf[:n]), " 200 ") {
			c.Close()
			return nil, fmt.Errorf("proxy CONNECT rejected: %s", strings.TrimSpace(string(buf[:n])))
		}
		return c, nil
	}
}

// errAs is a tiny shim around errors.As to keep this file's import list
// minimal — gobwas's StatusError is a concrete type, so a single type
// assertion path is enough.
func errAs(err error, target *ws.StatusError) bool {
	for e := err; e != nil; {
		if se, ok := e.(ws.StatusError); ok {
			*target = se
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := e.(unwrapper)
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}

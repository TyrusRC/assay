package racecond

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// h1LastByteBurst sends concurrency identical requests over keep-alive
// HTTP/1.1 connections, withholding the final byte of each request until a
// shared barrier releases. The release writes all final bytes in rapid
// succession, narrowing the arrival window from goroutine-scheduling jitter
// (5–50ms typical) to OS-level write fan-out (sub-ms typical).
//
// This is the open-source equivalent of Turbo Intruder's last-byte sync.
// It is not the H/2 single-packet attack — that requires HPACK + frame
// multiplexing on a single connection and is implemented separately — but
// it is fully sufficient for the race windows that matter in practice
// (DB-row update, coupon redemption, account credit), where the server's
// critical section is measured in tens of milliseconds.
func (d *Detector) h1LastByteBurst(ctx context.Context, target, method, body string, headers map[string]string, concurrency int, preSync time.Duration) ([]recordedResponse, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("parse target: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}

	addr := u.Host
	if !strings.Contains(addr, ":") {
		if u.Scheme == "https" {
			addr += ":443"
		} else {
			addr += ":80"
		}
	}

	prefix, finalByte := buildRawRequest(u, method, body, headers)
	if len(finalByte) == 0 {
		return nil, fmt.Errorf("buildRawRequest returned empty final byte")
	}

	conns := make([]net.Conn, concurrency)
	dialErrs := make([]error, concurrency)
	var dialWG sync.WaitGroup
	dialWG.Add(concurrency)
	dialDeadline, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dialCancel()
	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer dialWG.Done()
			c, err := dialOne(dialDeadline, u.Scheme, addr, u.Hostname())
			if err != nil {
				dialErrs[idx] = err
				return
			}
			conns[idx] = c
		}(i)
	}
	dialWG.Wait()

	defer func() {
		for _, c := range conns {
			if c != nil {
				_ = c.Close()
			}
		}
	}()

	// Bail if too many connections failed to dial — running a "race" against
	// a single warm connection would just be a normal request.
	live := 0
	for _, c := range conns {
		if c != nil {
			live++
		}
	}
	if live < 2 {
		var firstErr error
		for _, e := range dialErrs {
			if e != nil {
				firstErr = e
				break
			}
		}
		if firstErr != nil {
			return nil, fmt.Errorf("only %d/%d connections dialed: %w", live, concurrency, firstErr)
		}
		return nil, fmt.Errorf("only %d/%d connections dialed", live, concurrency)
	}

	// Phase 1: write prefixes on every live connection.
	var primeWG sync.WaitGroup
	primeErrs := make([]error, concurrency)
	for i, c := range conns {
		if c == nil {
			continue
		}
		primeWG.Add(1)
		go func(idx int, c net.Conn) {
			defer primeWG.Done()
			deadline := time.Now().Add(5 * time.Second)
			_ = c.SetWriteDeadline(deadline)
			if _, err := c.Write(prefix); err != nil {
				primeErrs[idx] = err
			}
		}(i, c)
	}
	primeWG.Wait()

	// Phase 2: let the prefix drain. This is the difference between a
	// "concurrent fan-out" and a synchronized release: by the time we
	// release the final byte, the server has fully parsed the request line
	// and headers and is sitting on a partial body, ready to act in the
	// shortest possible window when END_OF_REQUEST arrives.
	select {
	case <-time.After(preSync):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Phase 3: barrier release. All goroutines wait on the same channel.
	// Closing it lets every goroutine race to write its single byte; the
	// kernel typically dispatches all of these within the same scheduler
	// tick, packing them into a tight burst on the wire.
	barrier := make(chan struct{})
	results := make([]recordedResponse, concurrency)
	var burstWG sync.WaitGroup
	for i, c := range conns {
		if c == nil || primeErrs[i] != nil {
			results[i] = recordedResponse{Err: fmt.Errorf("prime failed: %w", primeErrs[i])}
			continue
		}
		burstWG.Add(1)
		go func(idx int, c net.Conn) {
			defer burstWG.Done()
			<-barrier
			_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := c.Write(finalByte); err != nil {
				results[idx] = recordedResponse{Err: err}
				return
			}
			_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
			results[idx] = readResponse(c)
		}(i, c)
	}
	close(barrier)
	burstWG.Wait()

	out := make([]recordedResponse, 0, concurrency)
	for _, r := range results {
		out = append(out, r)
	}
	return out, nil
}

// dialOne opens a single TCP (or TLS) connection. We disable Nagle so the
// final-byte write is not coalesced with anything else — this matters when
// the same goroutine is somehow scheduled to write again before the kernel
// flushes.
func dialOne(ctx context.Context, scheme, addr, sni string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if tcp, ok := raw.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	if scheme != "https" {
		return raw, nil
	}
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // detector-level scans run with --insecure already
		NextProtos:         []string{"http/1.1"},
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return tlsConn, nil
}

// buildRawRequest renders an HTTP/1.1 request to wire bytes and returns
// (everythingButTheFinalByte, finalByte). When the request has a body, the
// final byte split happens inside the body; otherwise the caller will split
// the headers themselves.
func buildRawRequest(u *url.URL, method, body string, headers map[string]string) (prefix, final []byte) {
	var b strings.Builder
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", strings.ToUpper(method), path)
	fmt.Fprintf(&b, "Host: %s\r\n", u.Host)
	fmt.Fprint(&b, "Connection: close\r\n")
	hasUA := false
	hasCL := false
	for k, v := range headers {
		if strings.EqualFold(k, "host") || strings.EqualFold(k, "connection") {
			continue
		}
		if strings.EqualFold(k, "user-agent") {
			hasUA = true
		}
		if strings.EqualFold(k, "content-length") {
			hasCL = true
		}
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	if !hasUA {
		fmt.Fprint(&b, "User-Agent: skws-racecond/1.0\r\n")
	}
	if body != "" && !hasCL {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	fmt.Fprint(&b, "\r\n")
	full := append([]byte(b.String()), []byte(body)...)
	if len(full) == 0 {
		return nil, nil
	}
	return full[:len(full)-1], full[len(full)-1:]
}

// readResponse reads a single HTTP/1.1 response from c and records the
// fields the analyzer needs.
func readResponse(c net.Conn) recordedResponse {
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return recordedResponse{Err: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil && err != io.EOF {
		return recordedResponse{StatusCode: resp.StatusCode, Err: err}
	}
	sum := sha256.Sum256(body)
	return recordedResponse{
		StatusCode:    resp.StatusCode,
		ContentLength: len(body),
		BodyHash:      hex.EncodeToString(sum[:8]),
		Body:          string(body),
	}
}

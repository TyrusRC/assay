package racecond

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// errH2NotNegotiated is returned when the server does not advertise h2 via
// TLS ALPN. Callers should fall back to SyncH1LastByte.
var errH2NotNegotiated = errors.New("server did not negotiate HTTP/2 via ALPN")

// h2SinglePacketBurst dispatches a multi-stream HTTP/2 burst over a single
// TLS connection, withholding the END_STREAM frame for every stream until
// a barrier release writes all of them in one TCP segment.
//
// This is the open-source equivalent of Kettle's HTTP/2 single-packet
// attack (PortSwigger 2023). Unlike H/1 last-byte sync — which depends on
// kernel scheduling to fan out N tiny writes across N TCP connections —
// the H/2 path uses one TCP segment containing N END_STREAM frames, so
// every request reaches END_OF_REQUEST in the same RTT slot. Arrival jitter
// drops from "sub-millisecond" to "sub-RTT" (sub-100µs LAN, sub-1ms WAN).
//
// Limitations:
//   - HTTPS-only. Cleartext h2c is rare in production and most front-ends
//     refuse it.
//   - The server's MAX_CONCURRENT_STREAMS setting caps concurrency; if
//     the server advertises a small value we trim the burst rather than
//     trip RST_STREAM(REFUSED_STREAM).
//   - Requests must fit inside the server's INITIAL_WINDOW_SIZE without
//     blocking on WINDOW_UPDATE. We do not implement flow control here;
//     race-condition probes are tiny by nature, so this is a non-issue.
func (d *Detector) h2SinglePacketBurst(ctx context.Context, target, method, body string, headers map[string]string, concurrency int, preSync time.Duration) ([]recordedResponse, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("parse target: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("h2 single-packet sync requires https; use SyncH1LastByte for cleartext targets")
	}
	addr := u.Host
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}

	tlsConn, err := dialH2(ctx, addr, u.Hostname())
	if err != nil {
		return nil, err
	}
	defer tlsConn.Close()

	// One single bufio.Writer over the TLS connection — every framer write
	// goes into this buffer, every Flush() becomes one TCP segment. The
	// "single packet" property hinges on phase 2 fitting in one Flush().
	bufW := bufio.NewWriterSize(tlsConn, 64*1024)
	if _, err := io.WriteString(bufW, http2.ClientPreface); err != nil {
		return nil, fmt.Errorf("write preface: %w", err)
	}
	framer := http2.NewFramer(bufW, tlsConn)
	framer.SetMaxReadFrameSize(1 << 20)

	if err := framer.WriteSettings(); err != nil {
		return nil, fmt.Errorf("write client settings: %w", err)
	}
	if err := bufW.Flush(); err != nil {
		return nil, fmt.Errorf("flush preface+settings: %w", err)
	}

	maxConcurrentStreams, err := readServerHandshake(framer, bufW)
	if err != nil {
		return nil, fmt.Errorf("h2 handshake: %w", err)
	}
	if maxConcurrentStreams > 0 && uint32(concurrency) > maxConcurrentStreams {
		concurrency = int(maxConcurrentStreams)
	}
	if concurrency < 2 {
		return nil, fmt.Errorf("h2 server advertised MAX_CONCURRENT_STREAMS=%d; need ≥ 2 for race probe", concurrency)
	}

	streamIDs := buildStreamIDs(concurrency)
	encBuf := &bytes.Buffer{}
	enc := hpack.NewEncoder(encBuf)

	if err := writePhase1(framer, enc, encBuf, u, method, body, headers, streamIDs); err != nil {
		return nil, fmt.Errorf("phase 1: %w", err)
	}
	if err := bufW.Flush(); err != nil {
		return nil, fmt.Errorf("flush phase 1: %w", err)
	}

	select {
	case <-time.After(preSync):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Phase 2: stage every END_STREAM-bearing final DATA frame into the
	// buffer, then flush once. This is the single TCP write the technique
	// is named after.
	for _, sid := range streamIDs {
		var finalData []byte
		if body != "" {
			finalData = []byte(body[len(body)-1:])
		}
		if err := framer.WriteData(sid, true, finalData); err != nil {
			return nil, fmt.Errorf("phase 2 stream %d: %w", sid, err)
		}
	}
	if err := bufW.Flush(); err != nil {
		return nil, fmt.Errorf("flush phase 2: %w", err)
	}

	return readH2Responses(framer, bufW, streamIDs, ctx)
}

// dialH2 opens a TLS connection with ALPN h2 negotiation. Returns
// errH2NotNegotiated if the server picks h1 or refuses h2.
func dialH2(ctx context.Context, addr, sni string) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}
	if tcp, ok := raw.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		// Offer h1 alongside h2 so strict-ALPN servers don't abort with
		// no_application_protocol when they speak only HTTP/1.1. The
		// caller distinguishes outcomes by checking NegotiatedProtocol.
		NextProtos: []string{"h2", "http/1.1"},
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		_ = tlsConn.Close()
		return nil, errH2NotNegotiated
	}
	return tlsConn, nil
}

// readServerHandshake reads SETTINGS / WINDOW_UPDATE / SETTINGS_ACK from
// the server until our own SETTINGS_ACK has been issued. Returns the
// server's MAX_CONCURRENT_STREAMS, or 0 if unset.
func readServerHandshake(framer *http2.Framer, bufW *bufio.Writer) (uint32, error) {
	deadline := time.Now().Add(5 * time.Second)
	var maxStreams uint32
	for {
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("handshake timeout")
		}
		f, err := framer.ReadFrame()
		if err != nil {
			return 0, err
		}
		switch ff := f.(type) {
		case *http2.SettingsFrame:
			if ff.IsAck() {
				return maxStreams, nil
			}
			ff.ForeachSetting(func(s http2.Setting) error {
				if s.ID == http2.SettingMaxConcurrentStreams {
					maxStreams = s.Val
				}
				return nil
			})
			if err := framer.WriteSettingsAck(); err != nil {
				return 0, err
			}
			if err := bufW.Flush(); err != nil {
				return 0, err
			}
		case *http2.WindowUpdateFrame:
			// Connection-level window; we don't track it (race probes are tiny).
		default:
			// Pre-settings: spec violations technically, but tolerate.
		}
	}
}

func buildStreamIDs(n int) []uint32 {
	ids := make([]uint32, n)
	for i := 0; i < n; i++ {
		ids[i] = uint32(1 + 2*i)
	}
	return ids
}

// writePhase1 emits HEADERS (no END_STREAM) and any body-prefix DATA
// frames for every stream. Phase 2 writes only the final END_STREAM frame
// for each stream.
func writePhase1(framer *http2.Framer, enc *hpack.Encoder, encBuf *bytes.Buffer, u *url.URL, method, body string, headers map[string]string, streamIDs []uint32) error {
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	for _, sid := range streamIDs {
		encBuf.Reset()
		_ = enc.WriteField(hpack.HeaderField{Name: ":method", Value: strings.ToUpper(method)})
		_ = enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
		_ = enc.WriteField(hpack.HeaderField{Name: ":authority", Value: u.Host})
		_ = enc.WriteField(hpack.HeaderField{Name: ":path", Value: path})
		if body != "" {
			_ = enc.WriteField(hpack.HeaderField{Name: "content-length", Value: strconv.Itoa(len(body))})
		}
		for k, v := range headers {
			lk := strings.ToLower(k)
			if shouldDropHeader(lk) {
				continue
			}
			_ = enc.WriteField(hpack.HeaderField{Name: lk, Value: v})
		}
		if err := framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      sid,
			BlockFragment: encBuf.Bytes(),
			EndStream:     false,
			EndHeaders:    true,
		}); err != nil {
			return err
		}
		if len(body) > 1 {
			if err := framer.WriteData(sid, false, []byte(body[:len(body)-1])); err != nil {
				return err
			}
		}
	}
	return nil
}

// shouldDropHeader strips connection-specific headers banned in HTTP/2
// (RFC 7540 §8.1.2.2) plus pseudo-headers a caller might accidentally
// include via the Headers map.
func shouldDropHeader(lower string) bool {
	if strings.HasPrefix(lower, ":") {
		return true
	}
	switch lower {
	case "host", "connection", "transfer-encoding", "upgrade",
		"keep-alive", "proxy-connection", "te":
		return true
	}
	return false
}

// h2StreamAccum holds the response state for a single stream while we
// reassemble HEADERS + DATA frames.
type h2StreamAccum struct {
	status int
	body   []byte
	done   bool
}

// readH2Responses reads frames until every stream has hit END_STREAM (or
// the connection closes / GOAWAY) and returns one recordedResponse per
// stream, in stream-ID order.
func readH2Responses(framer *http2.Framer, bufW *bufio.Writer, streamIDs []uint32, ctx context.Context) ([]recordedResponse, error) {
	streams := make(map[uint32]*h2StreamAccum, len(streamIDs))
	for _, sid := range streamIDs {
		streams[sid] = &h2StreamAccum{}
	}

	decoder := hpack.NewDecoder(4096, nil)
	deadline := time.Now().Add(15 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

readLoop:
	for {
		if time.Now().After(deadline) {
			break
		}
		f, err := framer.ReadFrame()
		if err != nil {
			break
		}
		sid := f.Header().StreamID
		s := streams[sid]

		switch ff := f.(type) {
		case *http2.HeadersFrame:
			if s == nil {
				continue
			}
			decoder.SetEmitFunc(func(hf hpack.HeaderField) {
				if hf.Name == ":status" {
					if v, err := strconv.Atoi(hf.Value); err == nil {
						s.status = v
					}
				}
			})
			if _, err := decoder.Write(ff.HeaderBlockFragment()); err != nil {
				return nil, fmt.Errorf("hpack decode stream %d: %w", sid, err)
			}
			if ff.HeadersEnded() && ff.StreamEnded() {
				s.done = true
			}
		case *http2.DataFrame:
			if s == nil {
				continue
			}
			s.body = append(s.body, ff.Data()...)
			if ff.StreamEnded() {
				s.done = true
			}
		case *http2.SettingsFrame:
			if !ff.IsAck() {
				_ = framer.WriteSettingsAck()
				_ = bufW.Flush()
			}
		case *http2.PingFrame:
			if !ff.IsAck() {
				_ = framer.WritePing(true, ff.Data)
				_ = bufW.Flush()
			}
		case *http2.GoAwayFrame:
			break readLoop
		case *http2.RSTStreamFrame:
			if s == nil {
				continue
			}
			s.done = true
			if s.status == 0 {
				s.status = 0 // explicitly zero so the analyzer treats it as "no answer"
			}
		}

		allDone := true
		for _, st := range streams {
			if !st.done {
				allDone = false
				break
			}
		}
		if allDone {
			break
		}
	}

	out := make([]recordedResponse, 0, len(streamIDs))
	for _, sid := range streamIDs {
		s := streams[sid]
		if s == nil {
			out = append(out, recordedResponse{Err: fmt.Errorf("no response for stream %d", sid)})
			continue
		}
		if s.status == 0 && len(s.body) == 0 {
			out = append(out, recordedResponse{Err: fmt.Errorf("stream %d closed without HEADERS", sid)})
			continue
		}
		sum := sha256.Sum256(s.body)
		out = append(out, recordedResponse{
			StatusCode:    s.status,
			ContentLength: len(s.body),
			BodyHash:      hex.EncodeToString(sum[:8]),
			Body:          string(s.body),
		})
	}
	return out, nil
}

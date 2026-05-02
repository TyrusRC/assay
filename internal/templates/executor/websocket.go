package executor

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates/matchers"
)

// WebSocketConfig configures WebSocket executor behaviour.
type WebSocketConfig struct {
	// Timeout for dialing and message exchange.
	Timeout time.Duration

	// ProxyURL routes WebSocket connections through an HTTP CONNECT proxy (e.g. http://127.0.0.1:8080 for Burp Suite).
	ProxyURL string
}

// DefaultWebSocketConfig returns sensible defaults.
func DefaultWebSocketConfig() *WebSocketConfig {
	return &WebSocketConfig{
		Timeout: 10 * time.Second,
	}
}

// WebSocketExecutor executes WebSocket-based template probes.
type WebSocketExecutor struct {
	matcherEngine *matchers.MatcherEngine
	config        *WebSocketConfig
}

// NewWebSocketExecutor creates a new WebSocket executor.
func NewWebSocketExecutor(config *WebSocketConfig) *WebSocketExecutor {
	if config == nil {
		config = DefaultWebSocketConfig()
	}
	return &WebSocketExecutor{
		matcherEngine: matchers.New(),
		config:        config,
	}
}

// Execute runs a WebSocket probe against a target.
// It builds the ws/wss URL, dials the server, sends each configured input,
// reads the response, and evaluates matchers against the combined data.
func (e *WebSocketExecutor) Execute(ctx context.Context, target string, probe *templates.WebsocketProbe) (*templates.ExecutionResult, error) {
	wsURL, err := buildWSURL(target, probe.Address)
	if err != nil {
		return nil, fmt.Errorf("websocket executor: build URL: %w", err)
	}

	dialCtx := ctx
	if e.config.Timeout > 0 {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, e.config.Timeout)
		defer cancel()
	}

	wsDialer := ws.Dialer{}
	if e.config.ProxyURL != "" {
		wsDialer.NetDial = e.makeProxyDialer()
	}

	conn, _, _, err := wsDialer.Dial(dialCtx, wsURL)
	if err != nil {
		return nil, fmt.Errorf("websocket executor: dial %s: %w", wsURL, err)
	}
	defer conn.Close()

	// Set a deadline on the underlying connection for read/write operations.
	if e.config.Timeout > 0 {
		if tc, ok := conn.(interface{ SetDeadline(time.Time) error }); ok {
			_ = tc.SetDeadline(time.Now().Add(e.config.Timeout))
		}
	}

	var allData strings.Builder

	for _, input := range probe.Inputs {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		data, decErr := decodeNetworkData(input.Data, input.Type)
		if decErr != nil {
			return nil, fmt.Errorf("websocket executor: decode input: %w", decErr)
		}

		if writeErr := wsutil.WriteClientText(conn, data); writeErr != nil {
			return nil, fmt.Errorf("websocket executor: write: %w", writeErr)
		}

		msg, readErr := wsutil.ReadServerText(conn)
		if readErr != nil {
			// Partial data is still useful for matching.
			break
		}
		allData.Write(msg)
	}

	combined := allData.String()

	resp := &matchers.Response{
		Body: combined,
		Raw:  combined,
		URL:  wsURL,
	}

	matched, extracts := e.matcherEngine.MatchAll(probe.Matchers, "", resp, nil)

	return &templates.ExecutionResult{
		Matched:       matched,
		URL:           wsURL,
		ExtractedData: extracts,
		Response:      combined,
		Request:       fmt.Sprintf("WS %s", wsURL),
		Timestamp:     time.Now(),
	}, nil
}

// makeProxyDialer returns a NetDial function that tunnels connections through
// an HTTP CONNECT proxy (e.g. Burp Suite at http://127.0.0.1:8080).
func (e *WebSocketExecutor) makeProxyDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	timeout := e.config.Timeout
	proxyURLStr := e.config.ProxyURL

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		proxyURL, err := url.Parse(proxyURLStr)
		if err != nil {
			// Fall back to direct dial on bad proxy URL.
			dialer := &net.Dialer{Timeout: timeout}
			return dialer.DialContext(ctx, network, addr)
		}

		proxyAddr := proxyURL.Host
		if !strings.Contains(proxyAddr, ":") {
			proxyAddr += ":8080"
		}

		dialer := &net.Dialer{Timeout: timeout}
		proxyConn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
		if err != nil {
			return nil, fmt.Errorf("proxy connection failed: %w", err)
		}

		connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
		if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
			proxyConn.Close()
			return nil, fmt.Errorf("proxy CONNECT write failed: %w", err)
		}

		buf := make([]byte, 1024)
		n, err := proxyConn.Read(buf)
		if err != nil {
			proxyConn.Close()
			return nil, fmt.Errorf("proxy CONNECT read failed: %w", err)
		}
		if !strings.Contains(string(buf[:n]), "200") {
			proxyConn.Close()
			return nil, fmt.Errorf("proxy CONNECT rejected: %s", strings.TrimSpace(string(buf[:n])))
		}

		return proxyConn, nil
	}
}

// buildWSURL constructs a WebSocket URL from the HTTP target and an optional
// address override declared in the probe.
//
// Scheme conversion:
//
//	http  → ws
//	https → wss
func buildWSURL(target, address string) (string, error) {
	base := target
	if address != "" {
		base = address
	}

	// If the address already uses a ws/wss scheme, use it directly.
	if strings.HasPrefix(base, "ws://") || strings.HasPrefix(base, "wss://") {
		return base, nil
	}

	u, err := url.Parse(base)
	if err != nil {
		// Fallback: treat as host:port.
		return "ws://" + base, nil
	}

	switch strings.ToLower(u.Scheme) {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	case "":
		// No scheme; assume ws.
		u.Scheme = "ws"
		if u.Host == "" {
			u.Host = u.Path
			u.Path = ""
		}
	}

	return u.String(), nil
}

// compile-time check: net.Conn satisfies the deadline interface used above.
var _ net.Conn = (*net.TCPConn)(nil)

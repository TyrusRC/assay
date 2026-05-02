package executor

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates/matchers"
)

const (
	// defaultWHOISServer is the IANA WHOIS server used when no server is specified.
	defaultWHOISServer = "whois.iana.org:43"
)

// WHOISExecutor executes WHOIS-based template queries.
type WHOISExecutor struct {
	matcherEngine *matchers.MatcherEngine
	timeout       time.Duration
	proxyURL      string
}

// NewWHOISExecutor creates a new WHOIS executor.
// proxyURL optionally routes WHOIS TCP connections through an HTTP CONNECT proxy
// (e.g. "http://127.0.0.1:8080" for Burp Suite). Pass an empty string to use direct connections.
func NewWHOISExecutor(timeout time.Duration, proxyURL string) *WHOISExecutor {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &WHOISExecutor{
		matcherEngine: matchers.New(),
		timeout:       timeout,
		proxyURL:      proxyURL,
	}
}

// Execute performs a WHOIS lookup for the target and evaluates matchers.
// The domain queried is extracted from the target URL; the server defaults
// to whois.iana.org:43 unless overridden in the query.
func (e *WHOISExecutor) Execute(ctx context.Context, target string, query *templates.WhoisQuery) (*templates.ExecutionResult, error) {
	domain := e.extractDomain(target)
	if domain == "" {
		return nil, fmt.Errorf("whois executor: could not extract domain from %q", target)
	}

	// Use the query's explicit query string when set; otherwise fall back to domain.
	queryStr := query.Query
	if queryStr == "" {
		queryStr = domain
	}

	server := query.Server
	if server == "" {
		server = defaultWHOISServer
	}
	// Ensure server has a port.
	if !strings.Contains(server, ":") {
		server = server + ":43"
	}

	raw, err := e.doQuery(ctx, server, queryStr)
	if err != nil {
		return nil, fmt.Errorf("whois executor: query %q via %s: %w", queryStr, server, err)
	}

	resp := &matchers.Response{
		Body: raw,
		Raw:  raw,
		URL:  target,
	}

	matched, extracts := e.matcherEngine.MatchAll(query.Matchers, "", resp, nil)

	return &templates.ExecutionResult{
		Matched:       matched,
		URL:           target,
		ExtractedData: extracts,
		Response:      raw,
		Request:       fmt.Sprintf("WHOIS %s @%s", queryStr, server),
		Timestamp:     time.Now(),
	}, nil
}

// doQuery opens a TCP connection to the WHOIS server (optionally via HTTP CONNECT
// proxy), sends the query, and reads the full response.
func (e *WHOISExecutor) doQuery(ctx context.Context, server, query string) (string, error) {
	dialer := &net.Dialer{Timeout: e.timeout}

	var conn net.Conn
	var err error

	if e.proxyURL != "" {
		conn, err = e.dialViaProxy(ctx, dialer, server)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", server)
	}
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if e.timeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(e.timeout)); err != nil {
			return "", fmt.Errorf("set deadline: %w", err)
		}
	}

	if _, err := fmt.Fprintf(conn, "%s\r\n", query); err != nil {
		return "", fmt.Errorf("write query: %w", err)
	}

	data, err := io.ReadAll(io.LimitReader(conn, 1024*1024)) // 1MB limit
	if err != nil {
		// Partial data on deadline expiry is still useful.
		if len(data) == 0 {
			return "", fmt.Errorf("read response: %w", err)
		}
	}

	return string(data), nil
}

// dialViaProxy connects to addr through an HTTP CONNECT proxy.
func (e *WHOISExecutor) dialViaProxy(ctx context.Context, dialer *net.Dialer, addr string) (net.Conn, error) {
	proxyURL, err := url.Parse(e.proxyURL)
	if err != nil {
		// Fall back to direct connection on bad proxy URL.
		return dialer.DialContext(ctx, "tcp", addr)
	}

	proxyAddr := proxyURL.Host
	if !strings.Contains(proxyAddr, ":") {
		proxyAddr += ":8080"
	}

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

// extractDomain strips the scheme, credentials, port, and path from a URL,
// returning only the bare hostname suitable for a WHOIS query.
func (e *WHOISExecutor) extractDomain(target string) string {
	if target == "" {
		return ""
	}
	// Add scheme if missing for url.Parse to work.
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return strings.TrimSuffix(target, "/")
}

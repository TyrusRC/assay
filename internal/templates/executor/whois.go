package executor

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/templates"
	"github.com/swiss-knife-for-web-security/skws/internal/templates/matchers"
)

const (
	// defaultWHOISServer is the IANA WHOIS server used when no server is specified.
	defaultWHOISServer = "whois.iana.org:43"
)

// WHOISExecutor executes WHOIS-based template queries.
type WHOISExecutor struct {
	matcherEngine *matchers.MatcherEngine
	timeout       time.Duration
}

// NewWHOISExecutor creates a new WHOIS executor.
func NewWHOISExecutor(timeout time.Duration) *WHOISExecutor {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &WHOISExecutor{
		matcherEngine: matchers.New(),
		timeout:       timeout,
	}
}

// Execute performs a WHOIS lookup for the target and evaluates matchers.
// The domain queried is extracted from the target URL; the server defaults
// to whois.iana.org:43 unless overridden in the query.
func (e *WHOISExecutor) Execute(ctx context.Context, target string, query *templates.WhoisQuery) (*templates.ExecutionResult, error) {
	domain := extractDomain(target)
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

// doQuery opens a TCP connection to the WHOIS server, sends the query, and
// reads the full response.
func (e *WHOISExecutor) doQuery(ctx context.Context, server, query string) (string, error) {
	dialer := &net.Dialer{Timeout: e.timeout}

	conn, err := dialer.DialContext(ctx, "tcp", server)
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

// extractDomain strips the scheme, credentials, port, and path from a URL,
// returning only the bare hostname suitable for a WHOIS query.
func extractDomain(target string) string {
	if target == "" {
		return ""
	}

	// Strip scheme.
	if idx := strings.Index(target, "://"); idx >= 0 {
		target = target[idx+3:]
	}

	// Strip credentials (user:pass@).
	if idx := strings.LastIndex(target, "@"); idx >= 0 {
		target = target[idx+1:]
	}

	// Strip path, query, and fragment.
	for _, sep := range []string{"/", "?", "#"} {
		if idx := strings.Index(target, sep); idx >= 0 {
			target = target[:idx]
		}
	}

	// Strip port.
	if h, _, err := net.SplitHostPort(target); err == nil {
		return h
	}

	return target
}

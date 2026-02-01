package smuggling

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
)

// SendRawRequest sends a raw HTTP request over a TCP socket.
// This bypasses standard http.Client which normalizes headers.
func SendRawRequest(ctx context.Context, addr string, request string, timeout time.Duration) (string, time.Duration, error) {
	// Check context before starting
	select {
	case <-ctx.Done():
		return "", 0, ctx.Err()
	default:
	}

	// Create dialer with timeout
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	// Connect
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", 0, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	// Set deadline
	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return "", 0, fmt.Errorf("set deadline failed: %w", err)
	}

	// Send request and measure time
	startTime := time.Now()

	_, err = conn.Write([]byte(request))
	if err != nil {
		return "", 0, fmt.Errorf("write failed: %w", err)
	}

	// Read response
	var response strings.Builder
	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return response.String(), time.Since(startTime), ctx.Err()
		default:
		}

		n, err := conn.Read(buf)
		if n > 0 {
			response.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}

	duration := time.Since(startTime)
	return response.String(), duration, nil
}

// ParseResponse parses a raw HTTP response string.
func ParseResponse(raw string) (*Response, error) {
	if raw == "" {
		return nil, errors.New("empty response")
	}

	resp := &Response{
		Headers: make(map[string]string),
		Raw:     raw,
	}

	// Split headers and body
	parts := strings.SplitN(raw, "\r\n\r\n", 2)
	if len(parts) < 1 {
		return nil, errors.New("invalid response format")
	}

	headerSection := parts[0]
	if len(parts) == 2 {
		resp.Body = parts[1]
	}

	// Split header section into lines
	lines := strings.Split(headerSection, "\r\n")
	if len(lines) == 0 {
		return nil, errors.New("invalid response format")
	}

	// Parse status line
	statusLine := strings.TrimSpace(lines[0])
	statusParts := strings.SplitN(statusLine, " ", 3)
	if len(statusParts) < 2 {
		return nil, errors.New("invalid status line")
	}

	statusCode, err := strconv.Atoi(statusParts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid status code: %w", err)
	}
	resp.StatusCode = statusCode

	if len(statusParts) >= 3 {
		resp.Status = statusParts[2]
	}

	// Parse headers (skip first line which is status)
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		if colonIdx := strings.Index(line, ":"); colonIdx > 0 {
			key := strings.TrimSpace(line[:colonIdx])
			value := strings.TrimSpace(line[colonIdx+1:])
			resp.Headers[key] = value
		}
	}

	return resp, nil
}

// ExtractHostPort extracts host and port from a target string.
func ExtractHostPort(target string) (string, string, error) {
	if target == "" {
		return "", "", errors.New("empty target")
	}

	// If it looks like a URL, parse it
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		u, err := url.Parse(target)
		if err != nil {
			return "", "", fmt.Errorf("invalid URL: %w", err)
		}

		host := u.Hostname()
		port := u.Port()
		if port == "" {
			if u.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		return host, port, nil
	}

	// Check if it already has a port
	if strings.Contains(target, ":") {
		host, port, err := net.SplitHostPort(target)
		if err != nil {
			return "", "", fmt.Errorf("invalid host:port: %w", err)
		}
		return host, port, nil
	}

	// Default to port 80
	return target, "80", nil
}

// CalculateTimingDifferential calculates the timing difference and whether it's significant.
func CalculateTimingDifferential(baseline, probe, threshold time.Duration) (time.Duration, bool) {
	if probe <= baseline {
		return 0, false
	}
	diff := probe - baseline
	return diff, diff >= threshold
}

// IsChunkedTerminator checks if the data contains a valid chunked encoding terminator.
func IsChunkedTerminator(data string) bool {
	return strings.Contains(data, "0\r\n\r\n")
}

// isTimeoutError checks if an error is a timeout error.
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	errStr := err.Error()
	return strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "deadline exceeded") ||
		strings.Contains(errStr, "i/o timeout")
}

// extractStatusCode extracts the HTTP status code from a response string.
func extractStatusCode(response string) int {
	resp, err := ParseResponse(response)
	if err != nil {
		return 0
	}
	return resp.StatusCode
}

// confidenceFromFloat converts a float confidence to core.Confidence.
func confidenceFromFloat(conf float64) core.Confidence {
	switch {
	case conf >= 0.95:
		return core.ConfidenceConfirmed
	case conf >= 0.8:
		return core.ConfidenceHigh
	case conf >= 0.5:
		return core.ConfidenceMedium
	default:
		return core.ConfidenceLow
	}
}

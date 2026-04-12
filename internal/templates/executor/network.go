// Package executor provides template execution capabilities.
package executor

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/templates"
	"github.com/swiss-knife-for-web-security/skws/internal/templates/matchers"
)

// NetworkConfig configures network executor behavior.
type NetworkConfig struct {
	// Timeout for connection establishment.
	Timeout time.Duration

	// ReadTimeout for reading data from connection.
	ReadTimeout time.Duration

	// WriteTimeout for writing data to connection.
	WriteTimeout time.Duration

	// ReadSize is the default buffer size for reading.
	ReadSize int

	// Dialer for custom connection options.
	Dialer *net.Dialer

	// ProxyURL routes TCP connections through an HTTP CONNECT proxy (e.g. http://127.0.0.1:8080 for Burp Suite).
	// SOCKS5 proxies are not supported for raw TCP; use an HTTP CONNECT-capable proxy.
	ProxyURL string
}

// DefaultNetworkConfig returns sensible defaults.
func DefaultNetworkConfig() *NetworkConfig {
	return &NetworkConfig{
		Timeout:      5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		ReadSize:     4096,
	}
}

// NetworkExecutor executes network/TCP-based template probes.
type NetworkExecutor struct {
	matcherEngine *matchers.MatcherEngine
	config        *NetworkConfig
	dialer        *net.Dialer
}

// NetworkResult contains the result of a network probe execution.
type NetworkResult struct {
	// Host that was connected to.
	Host string

	// Port that was connected to.
	Port string

	// Protocol used (tcp, udp).
	Protocol string

	// Whether connection was established.
	Connected bool

	// Banner received from the service (first response).
	Banner string

	// All response data received.
	ResponseData [][]byte

	// Raw combined response for matching.
	Raw string

	// Whether matchers matched.
	Matched bool

	// Extracted data from extractors.
	ExtractedData map[string][]string

	// Remote address.
	RemoteAddr string

	// Error if probe failed.
	Error error
}

// NewNetworkExecutor creates a new network executor.
func NewNetworkExecutor(config *NetworkConfig) *NetworkExecutor {
	if config == nil {
		config = DefaultNetworkConfig()
	}

	// Apply defaults for zero values
	if config.Timeout == 0 {
		config.Timeout = DefaultNetworkConfig().Timeout
	}
	if config.ReadTimeout == 0 {
		config.ReadTimeout = DefaultNetworkConfig().ReadTimeout
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = DefaultNetworkConfig().WriteTimeout
	}
	if config.ReadSize == 0 {
		config.ReadSize = DefaultNetworkConfig().ReadSize
	}

	dialer := config.Dialer
	if dialer == nil {
		dialer = &net.Dialer{
			Timeout: config.Timeout,
		}
	}

	return &NetworkExecutor{
		matcherEngine: matchers.New(),
		config:        config,
		dialer:        dialer,
	}
}

// Execute runs a network probe against a target.
func (e *NetworkExecutor) Execute(ctx context.Context, target string, probe *templates.NetworkProbe) (*NetworkResult, error) {
	result := &NetworkResult{
		Protocol:      "tcp",
		ExtractedData: make(map[string][]string),
	}

	// Build variables for interpolation
	vars := e.buildVariables(target)

	// Parse address
	host, port, err := parseNetworkAddress(target, probe.Host)
	if err != nil {
		result.Error = err
		return result, err
	}

	// Interpolate host
	host = e.interpolate(host, vars)
	port = e.interpolate(port, vars)

	result.Host = host
	result.Port = port

	// Determine read size
	readSize := e.config.ReadSize
	if probe.ReadSize > 0 {
		readSize = probe.ReadSize
	}

	// Connect with context (optionally through proxy)
	addr := net.JoinHostPort(host, port)
	conn, err := e.dialWithProxy(ctx, "tcp", addr)
	if err != nil {
		result.Error = fmt.Errorf("connection failed: %w", err)
		return result, nil // Return without error - connection failure is valid probe result
	}
	defer conn.Close()

	result.Connected = true
	result.RemoteAddr = conn.RemoteAddr().String()

	// Set up deadline for reads
	if e.config.ReadTimeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(e.config.ReadTimeout)); err != nil {
			result.Error = fmt.Errorf("failed to set read deadline: %w", err)
			return result, nil
		}
	}

	// Collect all response data
	var allData []byte

	// Read initial banner
	banner, readErr := e.readData(conn, readSize, false)
	if readErr != nil && readErr != io.EOF {
		// Timeout on read is not necessarily an error
		if !isTimeoutError(readErr) {
			// Some services don't send banners, this is okay
		}
	}
	if len(banner) > 0 {
		result.Banner = string(banner)
		result.ResponseData = append(result.ResponseData, banner)
		allData = append(allData, banner...)
	}

	// Execute input/output sequences
	for _, input := range probe.Inputs {
		select {
		case <-ctx.Done():
			result.Error = ctx.Err()
			return result, ctx.Err()
		default:
		}

		// Decode input data
		data, err := decodeNetworkData(input.Data, input.Type)
		if err != nil {
			result.Error = fmt.Errorf("failed to decode input data: %w", err)
			return result, err
		}

		// Set write deadline
		if e.config.WriteTimeout > 0 {
			if err := conn.SetWriteDeadline(time.Now().Add(e.config.WriteTimeout)); err != nil {
				result.Error = fmt.Errorf("failed to set write deadline: %w", err)
				return result, err
			}
		}

		// Send data
		if _, err := conn.Write(data); err != nil {
			result.Error = fmt.Errorf("failed to write data: %w", err)
			return result, err
		}

		// Determine read size for this input
		inputReadSize := readSize
		if input.Read > 0 {
			inputReadSize = input.Read
		}

		// Reset read deadline
		if e.config.ReadTimeout > 0 {
			if err := conn.SetReadDeadline(time.Now().Add(e.config.ReadTimeout)); err != nil {
				result.Error = fmt.Errorf("failed to set read deadline: %w", err)
				return result, err
			}
		}

		// Read response
		response, err := e.readData(conn, inputReadSize, probe.ReadAll)
		if err != nil && err != io.EOF && !isTimeoutError(err) {
			// Non-timeout read errors are logged but don't fail the probe
		}

		if len(response) > 0 {
			result.ResponseData = append(result.ResponseData, response)
			allData = append(allData, response...)

			// Set banner if not set
			if result.Banner == "" {
				result.Banner = string(response)
			}
		}
	}

	// Build raw response
	result.Raw = string(allData)

	// Build matcher response
	matcherResp := &matchers.Response{
		Body: result.Raw,
		Raw:  result.Raw,
	}

	// Evaluate matchers
	matched, extracts := e.matcherEngine.MatchAll(
		probe.Matchers,
		"", // Default to OR
		matcherResp,
		vars,
	)
	result.Matched = matched
	for k, v := range extracts {
		result.ExtractedData[k] = v
	}

	// Run extractors
	extracted := e.runExtractors(probe.Extractors, matcherResp, vars)
	for k, v := range extracted {
		result.ExtractedData[k] = v
	}

	return result, nil
}

// readData reads data from connection.
func (e *NetworkExecutor) readData(conn net.Conn, size int, readAll bool) ([]byte, error) {
	if readAll {
		return e.readAllData(conn, size)
	}

	buf := make([]byte, size)
	n, err := conn.Read(buf)
	if n > 0 {
		return buf[:n], err
	}
	return nil, err
}

// readAllData reads all available data from connection until EOF or timeout.
func (e *NetworkExecutor) readAllData(conn net.Conn, maxSize int) ([]byte, error) {
	var result []byte
	buf := make([]byte, 1024)

	for len(result) < maxSize {
		n, err := conn.Read(buf)
		if n > 0 {
			result = append(result, buf[:n]...)
		}
		if err != nil {
			if err == io.EOF || isTimeoutError(err) {
				break
			}
			return result, err
		}
	}

	if len(result) > maxSize {
		result = result[:maxSize]
	}

	return result, nil
}

// buildVariables builds variable context for interpolation.
func (e *NetworkExecutor) buildVariables(target string) map[string]interface{} {
	vars := make(map[string]interface{})

	// Parse target to extract hostname
	hostname := target
	if strings.HasPrefix(target, "tcp://") {
		hostname = strings.TrimPrefix(target, "tcp://")
	} else if strings.HasPrefix(target, "udp://") {
		hostname = strings.TrimPrefix(target, "udp://")
	}

	// Extract host and port
	if h, p, err := net.SplitHostPort(hostname); err == nil {
		vars["Hostname"] = h
		vars["Host"] = h
		vars["Port"] = p
	} else {
		vars["Hostname"] = hostname
		vars["Host"] = hostname
	}

	return vars
}

// interpolate replaces template variables in a string.
func (e *NetworkExecutor) interpolate(s string, vars map[string]interface{}) string {
	result := s
	for k, v := range vars {
		placeholder := "{{" + k + "}}"
		if str, ok := v.(string); ok {
			result = strings.ReplaceAll(result, placeholder, str)
		}
	}
	return result
}

// runExtractors runs extractors against the response.
func (e *NetworkExecutor) runExtractors(extractors []templates.Extractor, resp *matchers.Response, vars map[string]interface{}) map[string][]string {
	result := make(map[string][]string)

	for _, ext := range extractors {
		if ext.Internal {
			continue
		}

		var extracted []string
		content := resp.Body

		switch ext.Type {
		case "regex":
			extracted = extractRegex(ext.Regex, content, ext.Group)
		case "kval":
			// Not typically applicable for network probes
		case "json":
			extracted = extractJSON(ext.JSON, content)
		}

		if len(extracted) > 0 && ext.Name != "" {
			result[ext.Name] = extracted
		}
	}

	return result
}

// parseNetworkAddress parses the target and probe host to extract host and port.
func parseNetworkAddress(target string, probeHosts []string) (string, string, error) {
	// If probe has explicit hosts, use the first one
	if len(probeHosts) > 0 {
		addr := probeHosts[0]

		// Handle variable placeholders - return as-is for later interpolation
		if strings.Contains(addr, "{{") {
			// Extract port from after the colon
			if idx := strings.LastIndex(addr, ":"); idx > 0 {
				host := addr[:idx]
				port := addr[idx+1:]
				// Resolve {{Hostname}} placeholder
				if strings.Contains(host, "{{Hostname}}") {
					// Extract hostname from target
					targetHost := target
					if strings.HasPrefix(target, "tcp://") {
						targetHost = strings.TrimPrefix(target, "tcp://")
					}
					if h, _, err := net.SplitHostPort(targetHost); err == nil {
						host = h
					} else {
						host = targetHost
					}
				}
				return host, port, nil
			}
		}

		// Try to parse as host:port
		if h, p, err := net.SplitHostPort(addr); err == nil {
			return h, p, nil
		}

		// Assume it's just a host
		return addr, "", nil
	}

	// Parse target
	target = strings.TrimPrefix(target, "tcp://")
	target = strings.TrimPrefix(target, "udp://")

	if h, p, err := net.SplitHostPort(target); err == nil {
		return h, p, nil
	}

	return target, "", nil
}

// decodeNetworkData decodes input data based on type.
func decodeNetworkData(data string, dataType string) ([]byte, error) {
	switch strings.ToLower(dataType) {
	case "hex":
		// Remove spaces and decode hex
		cleaned := strings.ReplaceAll(data, " ", "")
		return hex.DecodeString(cleaned)
	case "text", "":
		return []byte(data), nil
	default:
		return []byte(data), nil
	}
}

// dialWithProxy dials a TCP connection, optionally tunnelling through an HTTP
// CONNECT proxy when NetworkConfig.ProxyURL is set.
func (e *NetworkExecutor) dialWithProxy(ctx context.Context, network, addr string) (net.Conn, error) {
	if e.config.ProxyURL == "" {
		return e.dialer.DialContext(ctx, network, addr)
	}

	proxyURL, err := url.Parse(e.config.ProxyURL)
	if err != nil {
		// Fall back to direct connection on bad proxy URL.
		return e.dialer.DialContext(ctx, network, addr)
	}

	proxyAddr := proxyURL.Host
	if !strings.Contains(proxyAddr, ":") {
		proxyAddr += ":8080"
	}

	proxyConn, err := e.dialer.DialContext(ctx, "tcp", proxyAddr)
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

// isTimeoutError checks if an error is a timeout error.
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

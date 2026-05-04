// Package executor provides template execution capabilities.
package executor

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates/matchers"
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


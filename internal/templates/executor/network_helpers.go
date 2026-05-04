package executor

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates/matchers"
)

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

	hostname := target
	if strings.HasPrefix(target, "tcp://") {
		hostname = strings.TrimPrefix(target, "tcp://")
	} else if strings.HasPrefix(target, "udp://") {
		hostname = strings.TrimPrefix(target, "udp://")
	}

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
	if len(probeHosts) > 0 {
		addr := probeHosts[0]

		if strings.Contains(addr, "{{") {
			if idx := strings.LastIndex(addr, ":"); idx > 0 {
				host := addr[:idx]
				port := addr[idx+1:]
				if strings.Contains(host, "{{Hostname}}") {
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

		if h, p, err := net.SplitHostPort(addr); err == nil {
			return h, p, nil
		}

		return addr, "", nil
	}

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

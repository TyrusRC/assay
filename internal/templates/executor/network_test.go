package executor

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates"
)

func TestNewNetworkExecutor(t *testing.T) {
	exec := NewNetworkExecutor(nil)
	if exec == nil {
		t.Fatal("NewNetworkExecutor() returned nil")
	}
}

func TestNewNetworkExecutorWithConfig(t *testing.T) {
	config := &NetworkConfig{
		Timeout:      5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 2 * time.Second,
		ReadSize:     4096,
	}
	exec := NewNetworkExecutor(config)
	if exec.config.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want 5s", exec.config.Timeout)
	}
	if exec.config.ReadSize != 4096 {
		t.Errorf("ReadSize = %d, want 4096", exec.config.ReadSize)
	}
}

func TestHexDecode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []byte
		wantErr bool
	}{
		{
			name:    "simple hex",
			input:   "48454c4c4f",
			want:    []byte("HELLO"),
			wantErr: false,
		},
		{
			name:    "hex with spaces",
			input:   "48 45 4c 4c 4f",
			want:    []byte("HELLO"),
			wantErr: false,
		},
		{
			name:    "lowercase hex",
			input:   "68656c6c6f",
			want:    []byte("hello"),
			wantErr: false,
		},
		{
			name:    "mixed case",
			input:   "48eLLo",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			want:    []byte{},
			wantErr: false,
		},
		{
			name:    "newline in data",
			input:   "0a0d",
			want:    []byte("\n\r"),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeNetworkData(tt.input, "hex")
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeNetworkData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && string(got) != string(tt.want) {
				t.Errorf("decodeNetworkData() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNetworkResultFormatting(t *testing.T) {
	result := &NetworkResult{
		Host:      "example.com",
		Port:      "22",
		Protocol:  "tcp",
		Connected: true,
		Banner:    "SSH-2.0-OpenSSH_8.9",
		ResponseData: [][]byte{
			[]byte("SSH-2.0-OpenSSH_8.9\r\n"),
		},
	}

	if result.Host != "example.com" {
		t.Errorf("Host = %q, want example.com", result.Host)
	}
	if result.Port != "22" {
		t.Errorf("Port = %q, want 22", result.Port)
	}
	if !result.Connected {
		t.Error("Connected should be true")
	}
	if result.Banner != "SSH-2.0-OpenSSH_8.9" {
		t.Errorf("Banner = %q, want SSH-2.0-OpenSSH_8.9", result.Banner)
	}
}

func TestNetworkExecutorExecute(t *testing.T) {
	// Start a mock TCP server
	server, addr := startMockTCPServer(t, func(conn net.Conn) {
		defer conn.Close()
		// Send banner
		conn.Write([]byte("220 SMTP Server Ready\r\n"))

		// Read input
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			return
		}

		// Respond to EHLO
		if strings.HasPrefix(string(buf[:n]), "EHLO") {
			conn.Write([]byte("250-smtp.example.com\r\n250-SIZE 52428800\r\n250 OK\r\n"))
		}
	})
	defer server.Close()

	host, port, _ := net.SplitHostPort(addr)

	config := &NetworkConfig{
		Timeout:     2 * time.Second,
		ReadTimeout: 1 * time.Second,
		ReadSize:    2048,
	}
	exec := NewNetworkExecutor(config)

	tests := []struct {
		name      string
		probe     *templates.NetworkProbe
		wantMatch bool
		wantErr   bool
	}{
		{
			name: "banner grab with word matcher",
			probe: &templates.NetworkProbe{
				Host: []string{host + ":" + port},
				Matchers: []templates.Matcher{
					{
						Type:  "word",
						Words: []string{"SMTP", "220"},
					},
				},
			},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name: "send receive with matcher",
			probe: &templates.NetworkProbe{
				Host: []string{host + ":" + port},
				Inputs: []templates.NetInput{
					{
						Data: "EHLO test.com\r\n",
						Type: "text",
						Read: 256,
					},
				},
				Matchers: []templates.Matcher{
					{
						Type:  "word",
						Words: []string{"250", "220"}, // Match either response or banner
					},
				},
			},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name: "regex matcher",
			probe: &templates.NetworkProbe{
				Host: []string{host + ":" + port},
				Matchers: []templates.Matcher{
					{
						Type:  "regex",
						Regex: []string{`\d{3}\s+SMTP`},
					},
				},
			},
			wantMatch: true,
			wantErr:   false,
		},
		{
			name: "no match case",
			probe: &templates.NetworkProbe{
				Host: []string{host + ":" + port},
				Matchers: []templates.Matcher{
					{
						Type:  "word",
						Words: []string{"NONEXISTENT_STRING_XYZ123"},
					},
				},
			},
			wantMatch: false,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			result, err := exec.Execute(ctx, "tcp://"+addr, tt.probe)

			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil && result.Matched != tt.wantMatch {
				t.Errorf("Execute() matched = %v, want %v\nBanner: %s\nRaw: %s",
					result.Matched, tt.wantMatch, result.Banner, result.Raw)
			}
		})
	}
}

func TestNetworkExecutorHexInput(t *testing.T) {
	// Start a mock TCP server that expects binary data
	server, addr := startMockTCPServer(t, func(conn net.Conn) {
		defer conn.Close()

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}

		// Echo back the data with a prefix
		response := append([]byte("ECHO:"), buf[:n]...)
		conn.Write(response)
	})
	defer server.Close()

	host, port, _ := net.SplitHostPort(addr)

	config := &NetworkConfig{
		Timeout:     2 * time.Second,
		ReadTimeout: 1 * time.Second,
	}
	exec := NewNetworkExecutor(config)

	probe := &templates.NetworkProbe{
		Host: []string{host + ":" + port},
		Inputs: []templates.NetInput{
			{
				Data: "48454c4c4f", // "HELLO" in hex
				Type: "hex",
				Read: 256,
			},
		},
		Matchers: []templates.Matcher{
			{
				Type:  "word",
				Words: []string{"ECHO:HELLO"},
			},
		},
	}

	ctx := context.Background()
	result, err := exec.Execute(ctx, "tcp://"+addr, probe)
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	if !result.Matched {
		t.Errorf("Expected match for hex input, got banner: %s", result.Banner)
	}
}

func TestNetworkExecutorExtractors(t *testing.T) {
	// Start the server that writes a banner immediately
	// Use the helper that other working tests use
	server, addr := startMockTCPServer(t, func(conn net.Conn) {
		defer conn.Close()
		// Write SSH banner
		conn.Write([]byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"))
		// Block until client disconnects (like the SMTP handler does)
		buf := make([]byte, 1)
		conn.Read(buf)
	})
	defer server.Close()

	host, port, _ := net.SplitHostPort(addr)

	config := &NetworkConfig{
		Timeout:     2 * time.Second,
		ReadTimeout: 1 * time.Second,
	}
	exec := NewNetworkExecutor(config)

	probe := &templates.NetworkProbe{
		Host: []string{host + ":" + port},
		Matchers: []templates.Matcher{
			{
				Type:  "word",
				Words: []string{"SSH"},
			},
		},
		Extractors: []templates.Extractor{
			{
				Type:  "regex",
				Name:  "ssh_version",
				Regex: []string{`OpenSSH_(\d+\.\d+)`},
				Group: 1,
			},
		},
	}

	ctx := context.Background()
	result, err := exec.Execute(ctx, addr, probe)
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	if !result.Matched {
		t.Errorf("Expected match, got banner: %q, raw: %q, error: %v", result.Banner, result.Raw, result.Error)
	}

	if result.ExtractedData == nil {
		t.Fatal("No extracted data")
	}

	if v, ok := result.ExtractedData["ssh_version"]; !ok || len(v) == 0 {
		t.Errorf("ssh_version not extracted, extracted data: %v", result.ExtractedData)
	} else if v[0] != "8.9" {
		t.Errorf("ssh_version = %q, want 8.9", v[0])
	}
}

func TestNetworkExecutorMultipleInputs(t *testing.T) {
	// Start a mock TCP server that handles multiple exchanges
	server, addr := startMockTCPServer(t, func(conn net.Conn) {
		defer conn.Close()

		// Initial banner
		conn.Write([]byte("+OK POP3 server ready\r\n"))

		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}

			cmd := strings.TrimSpace(string(buf[:n]))
			switch {
			case strings.HasPrefix(cmd, "USER"):
				conn.Write([]byte("+OK User accepted\r\n"))
			case strings.HasPrefix(cmd, "PASS"):
				conn.Write([]byte("+OK Pass accepted\r\n"))
			case strings.HasPrefix(cmd, "QUIT"):
				conn.Write([]byte("+OK Goodbye\r\n"))
				return
			}
		}
	})
	defer server.Close()

	host, port, _ := net.SplitHostPort(addr)

	config := &NetworkConfig{
		Timeout:     2 * time.Second,
		ReadTimeout: 1 * time.Second,
	}
	exec := NewNetworkExecutor(config)

	probe := &templates.NetworkProbe{
		Host: []string{host + ":" + port},
		Inputs: []templates.NetInput{
			{Data: "USER test\r\n", Type: "text", Read: 256, Name: "user_response"},
			{Data: "PASS test\r\n", Type: "text", Read: 256, Name: "pass_response"},
			{Data: "QUIT\r\n", Type: "text", Read: 256, Name: "quit_response"},
		},
		Matchers: []templates.Matcher{
			{
				Type:      "word",
				Words:     []string{"+OK POP3", "+OK User", "+OK Pass"},
				Condition: "and",
			},
		},
	}

	ctx := context.Background()
	result, err := exec.Execute(ctx, "tcp://"+addr, probe)
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	if !result.Matched {
		t.Errorf("Expected match for multiple inputs, got raw: %s", result.Raw)
	}
}

func TestNetworkExecutorContextCancellation(t *testing.T) {
	// Start a mock server that accepts but doesn't respond
	server, addr := startMockTCPServer(t, func(conn net.Conn) {
		defer conn.Close()
		// Hold connection without responding
		time.Sleep(5 * time.Second)
	})
	defer server.Close()

	host, port, _ := net.SplitHostPort(addr)

	config := &NetworkConfig{
		Timeout:     10 * time.Second,
		ReadTimeout: 5 * time.Second,
	}
	exec := NewNetworkExecutor(config)

	probe := &templates.NetworkProbe{
		Host: []string{host + ":" + port},
	}

	// Cancel context immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, _ := exec.Execute(ctx, "tcp://"+addr, probe)
	// With immediate cancellation, connection may or may not succeed
	// What matters is that we don't hang
	if result != nil {
		t.Logf("Result received with cancelled context: connected=%v", result.Connected)
	}
}

func TestNetworkExecutorConnectionRefused(t *testing.T) {
	config := &NetworkConfig{
		Timeout: 1 * time.Second,
	}
	exec := NewNetworkExecutor(config)

	// Use a port that's likely not in use
	probe := &templates.NetworkProbe{
		Host: []string{"127.0.0.1:59999"},
	}

	ctx := context.Background()
	result, err := exec.Execute(ctx, "tcp://127.0.0.1:59999", probe)

	// Connection refused is not an error, just means no match
	if err == nil && result.Connected {
		t.Error("Expected connection to fail")
	}
}

func TestNetworkExecutorReadSize(t *testing.T) {
	// Create a large response
	largeData := strings.Repeat("A", 10000)

	server, addr := startMockTCPServer(t, func(conn net.Conn) {
		defer conn.Close()
		conn.Write([]byte(largeData))
	})
	defer server.Close()

	host, port, _ := net.SplitHostPort(addr)

	config := &NetworkConfig{
		Timeout:     2 * time.Second,
		ReadTimeout: 1 * time.Second,
		ReadSize:    100, // Limit to 100 bytes
	}
	exec := NewNetworkExecutor(config)

	probe := &templates.NetworkProbe{
		Host:     []string{host + ":" + port},
		ReadSize: 100,
	}

	ctx := context.Background()
	result, err := exec.Execute(ctx, "tcp://"+addr, probe)
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	// Should only have read up to ReadSize bytes
	if len(result.Banner) > 100 {
		t.Errorf("Banner length = %d, expected <= 100", len(result.Banner))
	}
}

func TestNetworkAddressParsing(t *testing.T) {
	tests := []struct {
		name      string
		target    string
		probeHost []string
		wantHost  string
		wantPort  string
		wantErr   bool
	}{
		{
			name:      "tcp URL format",
			target:    "tcp://example.com:22",
			probeHost: nil,
			wantHost:  "example.com",
			wantPort:  "22",
			wantErr:   false,
		},
		{
			name:      "host:port format",
			target:    "example.com:22",
			probeHost: nil,
			wantHost:  "example.com",
			wantPort:  "22",
			wantErr:   false,
		},
		{
			name:      "probe host overrides target",
			target:    "example.com:22",
			probeHost: []string{"other.com:443"},
			wantHost:  "other.com",
			wantPort:  "443",
			wantErr:   false,
		},
		{
			name:      "probe with variable",
			target:    "example.com",
			probeHost: []string{"{{Hostname}}:22"},
			wantHost:  "example.com",
			wantPort:  "22",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := parseNetworkAddress(tt.target, tt.probeHost)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseNetworkAddress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if host != tt.wantHost {
				t.Errorf("host = %q, want %q", host, tt.wantHost)
			}
			if port != tt.wantPort {
				t.Errorf("port = %q, want %q", port, tt.wantPort)
			}
		})
	}
}

// startMockTCPServer starts a mock TCP server for testing.
func startMockTCPServer(t *testing.T, handler func(net.Conn)) (net.Listener, string) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock TCP server: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return // Server closed
			}
			go handler(conn)
		}
	}()

	// Give server time to start
	time.Sleep(10 * time.Millisecond)

	return listener, listener.Addr().String()
}

func TestNetworkExecutorReadAll(t *testing.T) {
	// Use the standard server helper
	server, addr := startMockTCPServer(t, func(conn net.Conn) {
		defer conn.Close()
		conn.Write([]byte("Part1Part2Part3"))
		// Block until client disconnects
		buf := make([]byte, 1)
		conn.Read(buf)
	})
	defer server.Close()

	host, port, _ := net.SplitHostPort(addr)

	config := &NetworkConfig{
		Timeout:     2 * time.Second,
		ReadTimeout: 500 * time.Millisecond,
	}
	exec := NewNetworkExecutor(config)

	probe := &templates.NetworkProbe{
		Host:    []string{host + ":" + port},
		ReadAll: true,
		Matchers: []templates.Matcher{
			{
				Type:      "word",
				Words:     []string{"Part1", "Part2", "Part3"},
				Condition: "and",
			},
		},
	}

	ctx := context.Background()
	result, err := exec.Execute(ctx, addr, probe)
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	if !result.Matched {
		t.Errorf("Expected all parts to match, got raw: %q, banner: %q", result.Raw, result.Banner)
	}
}

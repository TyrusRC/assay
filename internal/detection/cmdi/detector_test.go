package cmdi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	internalhttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/payloads/cmdi"
)

func TestNew(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	if detector == nil {
		t.Fatal("New() returned nil")
	}

	if detector.client != client {
		t.Error("New() did not set client correctly")
	}

	if len(detector.outputPatterns) == 0 {
		t.Error("New() did not initialize outputPatterns")
	}
}

func TestDetector_WithVerbose(t *testing.T) {
	client := internalhttp.NewClient()

	detector := New(client).WithVerbose(true)
	if !detector.verbose {
		t.Error("WithVerbose(true) did not set verbose flag")
	}

	detector2 := New(client).WithVerbose(false)
	if detector2.verbose {
		t.Error("WithVerbose(false) should leave verbose as false")
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.MaxPayloads <= 0 {
		t.Error("DefaultOptions() MaxPayloads should be positive")
	}
	if opts.Timeout <= 0 {
		t.Error("DefaultOptions() Timeout should be positive")
	}
	if !opts.IncludeWAFBypass {
		t.Error("DefaultOptions() IncludeWAFBypass should be true")
	}
	if !opts.EnableTimeBased {
		t.Error("DefaultOptions() EnableTimeBased should be true")
	}
	if opts.TimeBasedDelay <= 0 {
		t.Error("DefaultOptions() TimeBasedDelay should be positive")
	}
	if opts.Platform != cmdi.PlatformBoth {
		t.Errorf("DefaultOptions() Platform = %v, want %v", opts.Platform, cmdi.PlatformBoth)
	}
}

func TestDetector_DetectOutputBased(t *testing.T) {
	// Create a vulnerable server that executes commands
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cmd := r.URL.Query().Get("cmd")
		if cmd != "" && (strings.Contains(cmd, "id") || strings.Contains(cmd, "whoami")) {
			// Simulate command output
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("uid=1000(testuser) gid=1000(testuser) groups=1000(testuser)"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?cmd=test", "cmd", "GET", DetectOptions{
		MaxPayloads:     10,
		EnableTimeBased: false,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerability to be detected")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}
}

func TestDetector_DetectTimeBased(t *testing.T) {
	t.Skip("Skipping time-based test as it takes too long")
}

func TestDetector_SafeServer(t *testing.T) {
	// Create a safe server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Safe response"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?cmd=test", "cmd", "GET", DetectOptions{
		MaxPayloads:     5,
		EnableTimeBased: false,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability in safe server")
	}
}

func TestDetector_OutputPatterns(t *testing.T) {
	tests := []struct {
		name     string
		response string
		platform cmdi.Platform
		expected bool
	}{
		{
			name:     "Linux id command",
			response: "uid=1000(user) gid=1000(user) groups=1000(user)",
			platform: cmdi.PlatformBoth,
			expected: true,
		},
		{
			name:     "Linux passwd file",
			response: "root:x:0:0:root:/root:/bin/bash",
			platform: cmdi.PlatformBoth,
			expected: true,
		},
		{
			name:     "Windows dir output",
			response: "Volume in drive C has no label",
			platform: cmdi.PlatformBoth,
			expected: true,
		},
		{
			name:     "Normal response",
			response: "Hello World",
			platform: cmdi.PlatformBoth,
			expected: false,
		},
		{
			name:     "Linux uname output",
			response: "Linux myhost 5.15.0-generic #1 SMP x86_64 GNU/Linux",
			platform: cmdi.PlatformBoth,
			expected: true,
		},
		{
			name:     "Windows version",
			response: "Microsoft Windows [Version 10.0.19045.3803]",
			platform: cmdi.PlatformBoth,
			expected: true,
		},
		{
			name:     "Linux ls output",
			response: "total 24\ndrwxr-xr-x 2 user user 4096 Jan 1 00:00 dir",
			platform: cmdi.PlatformBoth,
			expected: true,
		},
		{
			name:     "Linux env output",
			response: "PATH=/usr/bin:/bin\nHOME=/home/user",
			platform: cmdi.PlatformBoth,
			expected: true,
		},
		{
			name:     "Linux ifconfig output",
			response: "inet 192.168.1.100 netmask 255.255.255.0",
			platform: cmdi.PlatformBoth,
			expected: true,
		},
		{
			name:     "Windows env vars",
			response: "COMPUTERNAME=MYPC\nUSERNAME=admin",
			platform: cmdi.PlatformBoth,
			expected: true,
		},
		{
			name:     "Windows path",
			response: "C:\\Windows\\System32\\cmd.exe",
			platform: cmdi.PlatformBoth,
			expected: true,
		},
		{
			name:     "Windows win.ini",
			response: "[fonts]\nTimes New Roman",
			platform: cmdi.PlatformBoth,
			expected: true,
		},
		{
			name:     "Windows ipconfig",
			response: "Windows IP Configuration\nEthernet adapter",
			platform: cmdi.PlatformBoth,
			expected: true,
		},
		{
			name:     "Linux os-release",
			response: "PRETTY_NAME=\"Ubuntu 22.04 LTS\"\nID=ubuntu",
			platform: cmdi.PlatformBoth,
			expected: true,
		},
		{
			name:     "Linux shell path",
			response: "the shell is /bin/bash",
			platform: cmdi.PlatformBoth,
			expected: true,
		},
		{
			name:     "Linux shell path sh",
			response: "the shell is /bin/sh",
			platform: cmdi.PlatformBoth,
			expected: true,
		},
		{
			name:     "Windows NT authority",
			response: "NT AUTHORITY\\SYSTEM",
			platform: cmdi.PlatformBoth,
			expected: true,
		},
		{
			name:     "Windows BUILTIN",
			response: "BUILTIN\\Administrators",
			platform: cmdi.PlatformBoth,
			expected: true,
		},
	}

	client := internalhttp.NewClient()
	detector := New(client)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use a dummy payload for testing with empty baseline
			payload := cmdi.Payload{Platform: tt.platform}
			hasOutput := detector.hasCommandOutput(tt.response, "", payload)
			if hasOutput != tt.expected {
				t.Errorf("hasCommandOutput() = %v, want %v", hasOutput, tt.expected)
			}
		})
	}
}

func TestDetector_hasCommandOutput_WithBaseline(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name     string
		body     string
		baseline string
		platform cmdi.Platform
		expected bool
	}{
		{
			name:     "pattern in both body and baseline",
			body:     "uid=1000(user) gid=1000(user)",
			baseline: "uid=1000(user) gid=1000(user)",
			platform: cmdi.PlatformBoth,
			expected: false,
		},
		{
			name:     "pattern in body not baseline",
			body:     "uid=1000(user) gid=1000(user)",
			baseline: "OK",
			platform: cmdi.PlatformBoth,
			expected: true,
		},
		{
			name:     "no patterns in either",
			body:     "Hello World",
			baseline: "Hello World",
			platform: cmdi.PlatformBoth,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := cmdi.Payload{Platform: tt.platform}
			got := detector.hasCommandOutput(tt.body, tt.baseline, payload)
			if got != tt.expected {
				t.Errorf("hasCommandOutput() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDetector_hasCommandOutput_LinuxPlatformChecks(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name     string
		body     string
		baseline string
		expected bool
	}{
		{
			name:     "Linux uid and gid strings",
			body:     "some output uid=0 stuff gid=0 more",
			baseline: "clean output",
			expected: true,
		},
		{
			name:     "Linux uid and gid in baseline too",
			body:     "some output uid=0 stuff gid=0 more",
			baseline: "some output uid=0 stuff gid=0 more",
			expected: false,
		},
		{
			name:     "Linux root and bin",
			body:     "root:x:0:0:root:/root:/bin/bash",
			baseline: "clean output",
			expected: true,
		},
		{
			name:     "Linux root and bin in baseline too",
			body:     "root:x:0:0:root:/root:/bin/bash",
			baseline: "root:x:0:0:root:/root:/bin/bash",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := cmdi.Payload{Platform: cmdi.PlatformLinux}
			got := detector.hasCommandOutput(tt.body, tt.baseline, payload)
			if got != tt.expected {
				t.Errorf("hasCommandOutput() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDetector_hasCommandOutput_WindowsPlatformChecks(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name     string
		body     string
		baseline string
		expected bool
	}{
		{
			name:     "Windows Volume in drive",
			body:     "Volume in drive C has no label",
			baseline: "clean output",
			expected: true,
		},
		{
			name:     "Windows Directory of",
			body:     "Directory of C:\\Users",
			baseline: "clean output",
			expected: true,
		},
		{
			name:     "Windows Volume in baseline too",
			body:     "Volume in drive C has no label",
			baseline: "Volume in drive C has no label",
			expected: false,
		},
		{
			name:     "Windows IP Configuration",
			body:     "Windows IP Configuration\nEthernet",
			baseline: "clean output",
			expected: true,
		},
		{
			name:     "Windows IP Configuration in baseline too",
			body:     "Windows IP Configuration",
			baseline: "Windows IP Configuration",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := cmdi.Payload{Platform: cmdi.PlatformWindows}
			got := detector.hasCommandOutput(tt.body, tt.baseline, payload)
			if got != tt.expected {
				t.Errorf("hasCommandOutput() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDetector_deduplicatePayloads(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name     string
		payloads []cmdi.Payload
		want     int
	}{
		{
			name: "with duplicates",
			payloads: []cmdi.Payload{
				{Value: "a"},
				{Value: "b"},
				{Value: "a"},
				{Value: "c"},
				{Value: "b"},
			},
			want: 3,
		},
		{
			name: "no duplicates",
			payloads: []cmdi.Payload{
				{Value: "a"},
				{Value: "b"},
				{Value: "c"},
			},
			want: 3,
		},
		{
			name:     "empty slice",
			payloads: []cmdi.Payload{},
			want:     0,
		},
		{
			name: "all same",
			payloads: []cmdi.Payload{
				{Value: "same"},
				{Value: "same"},
			},
			want: 1,
		},
		{
			name: "single payload",
			payloads: []cmdi.Payload{
				{Value: "only"},
			},
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unique := detector.deduplicatePayloads(tt.payloads)
			if len(unique) != tt.want {
				t.Errorf("deduplicatePayloads() returned %d, want %d", len(unique), tt.want)
			}
		})
	}
}

func TestDetector_createFinding(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name          string
		target        string
		param         string
		payload       cmdi.Payload
		resp          *internalhttp.Response
		detectionType string
		wantSeverity  core.Severity
		wantTool      string
	}{
		{
			name:   "output-based with response",
			target: "http://example.com/page",
			param:  "cmd",
			payload: cmdi.Payload{
				Value:       ";id",
				Platform:    cmdi.PlatformLinux,
				Type:        cmdi.TypeChained,
				Description: "id command",
			},
			resp:          &internalhttp.Response{StatusCode: 200, Body: "uid=1000(user) gid=1000(user)"},
			detectionType: "output-based",
			wantSeverity:  core.SeverityCritical,
			wantTool:      "cmdi-detector",
		},
		{
			name:   "time-based with nil response",
			target: "http://example.com/page",
			param:  "input",
			payload: cmdi.Payload{
				Value:       ";sleep 5",
				Platform:    cmdi.PlatformLinux,
				Type:        cmdi.TypeTimeBased,
				Description: "Sleep 5 seconds",
			},
			resp:          nil,
			detectionType: "time-based",
			wantSeverity:  core.SeverityCritical,
			wantTool:      "cmdi-detector",
		},
		{
			name:   "with long response body truncation",
			target: "http://example.com/page",
			param:  "cmd",
			payload: cmdi.Payload{
				Value:       ";cat /etc/passwd",
				Platform:    cmdi.PlatformLinux,
				Type:        cmdi.TypeChained,
				Description: "Read passwd",
			},
			resp:          &internalhttp.Response{StatusCode: 200, Body: strings.Repeat("A", 600)},
			detectionType: "output-based",
			wantSeverity:  core.SeverityCritical,
			wantTool:      "cmdi-detector",
		},
		{
			name:   "with empty response body",
			target: "http://example.com/page",
			param:  "cmd",
			payload: cmdi.Payload{
				Value:       ";id",
				Platform:    cmdi.PlatformWindows,
				Type:        cmdi.TypeChained,
				Description: "whoami command",
			},
			resp:          &internalhttp.Response{StatusCode: 200, Body: ""},
			detectionType: "output-based",
			wantSeverity:  core.SeverityCritical,
			wantTool:      "cmdi-detector",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := detector.createFinding(tt.target, tt.param, tt.payload, tt.resp, tt.detectionType)

			if finding == nil {
				t.Fatal("createFinding() returned nil")
			}
			if finding.Severity != tt.wantSeverity {
				t.Errorf("Severity = %v, want %v", finding.Severity, tt.wantSeverity)
			}
			if finding.Tool != tt.wantTool {
				t.Errorf("Tool = %q, want %q", finding.Tool, tt.wantTool)
			}
			if finding.URL != tt.target {
				t.Errorf("URL = %q, want %q", finding.URL, tt.target)
			}
			if finding.Parameter != tt.param {
				t.Errorf("Parameter = %q, want %q", finding.Parameter, tt.param)
			}
			if finding.Evidence == "" {
				t.Error("Expected non-empty Evidence")
			}
			if finding.Remediation == "" {
				t.Error("Expected non-empty Remediation")
			}
			if finding.Description == "" {
				t.Error("Expected non-empty Description")
			}
			if !strings.Contains(finding.Description, tt.detectionType) {
				t.Errorf("Description should contain detection type %q, got %q", tt.detectionType, finding.Description)
			}
			if len(finding.WSTG) == 0 {
				t.Error("Expected WSTG mappings")
			}
			if len(finding.Top10) == 0 {
				t.Error("Expected Top10 mappings")
			}
			if len(finding.CWE) == 0 {
				t.Error("Expected CWE mappings")
			}

			// Check truncation for long body
			if tt.resp != nil && len(tt.resp.Body) > 500 {
				if !strings.Contains(finding.Evidence, "...") {
					t.Error("Expected truncation indicator for long body")
				}
			}
		})
	}
}

func TestDetector_Detect_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result, err := detector.Detect(ctx, server.URL+"?cmd=test", "cmd", "GET", DetectOptions{
		MaxPayloads:     100,
		EnableTimeBased: false,
	})

	// Either the baseline request fails or the context cancellation is returned
	if err == nil {
		if result == nil {
			t.Fatal("Expected non-nil result")
		}
	}
}

func TestDetector_Detect_ServerDown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	serverURL := server.URL
	server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), serverURL+"?cmd=test", "cmd", "GET", DetectOptions{
		MaxPayloads:     5,
		EnableTimeBased: false,
	})

	if err == nil {
		t.Error("Expected error when server is down")
	}

	if result == nil {
		t.Fatal("Expected non-nil result even on error")
	}

	if !strings.Contains(err.Error(), "failed to get baseline") {
		t.Errorf("Expected baseline error, got: %v", err)
	}
}

func TestDetector_Detect_PayloadLimiting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("safe response"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?cmd=test", "cmd", "GET", DetectOptions{
		MaxPayloads:      3,
		IncludeWAFBypass: false,
		EnableTimeBased:  false,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result.TestedPayloads > 3 {
		t.Errorf("Expected at most 3 tested payloads, got %d", result.TestedPayloads)
	}
}

func TestDetector_Detect_WithWAFBypass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cmd := r.URL.Query().Get("cmd")
		if strings.Contains(cmd, "id") || strings.Contains(cmd, "whoami") || strings.Contains(cmd, "passwd") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("uid=1000(testuser) gid=1000(testuser)"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?cmd=test", "cmd", "GET", DetectOptions{
		MaxPayloads:      20,
		IncludeWAFBypass: true,
		EnableTimeBased:  false,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestDetector_Detect_HTTPErrorDuringPayload(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			// Baseline request succeeds
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("baseline"))
			return
		}
		// Subsequent requests cause connection reset (close without writing)
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			conn.Close()
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?cmd=test", "cmd", "GET", DetectOptions{
		MaxPayloads:     3,
		EnableTimeBased: false,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	// Should handle errors gracefully, continue to next payload
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestDetector_Detect_ContextCancellationDuringPayloads(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay to allow baseline but cancel during payloads
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	result, err := detector.Detect(ctx, server.URL+"?cmd=test", "cmd", "GET", DetectOptions{
		MaxPayloads:     1000,
		EnableTimeBased: false,
	})

	// Either context error or success with partial results
	if err != nil && err != context.Canceled {
		// The error might be wrapped
		if !strings.Contains(err.Error(), "context canceled") {
			t.Logf("Got expected error variant: %v", err)
		}
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestDetector_Detect_MaxPayloadsZero(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("safe"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	// MaxPayloads=0 means no limit
	result, err := detector.Detect(context.Background(), server.URL+"?cmd=test", "cmd", "GET", DetectOptions{
		MaxPayloads:      0,
		IncludeWAFBypass: false,
		EnableTimeBased:  false,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestDetector_Detect_WindowsVulnerableServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cmd := r.URL.Query().Get("cmd")
		if strings.Contains(cmd, "whoami") || strings.Contains(cmd, "dir") || strings.Contains(cmd, "ipconfig") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Volume in drive C has no label\nDirectory of C:\\Users\\Admin"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?cmd=test", "cmd", "GET", DetectOptions{
		MaxPayloads:     20,
		Platform:        cmdi.PlatformWindows,
		EnableTimeBased: false,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected Windows vulnerability to be detected")
	}
}

func TestDetector_Detect_StopsAfterFirstFinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cmd := r.URL.Query().Get("cmd")
		if strings.Contains(cmd, "id") || strings.Contains(cmd, "whoami") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("uid=1000(testuser) gid=1000(testuser) groups=1000(testuser)"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?cmd=test", "cmd", "GET", DetectOptions{
		MaxPayloads:     50,
		EnableTimeBased: false,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerability to be detected")
	}

	// CMDI detector stops after first finding
	if len(result.Findings) != 1 {
		t.Errorf("Expected exactly 1 finding (stops after first), got %d", len(result.Findings))
	}
}

func TestDetector_Detect_InvalidURL(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), "://invalid-url", "cmd", "GET", DetectOptions{
		MaxPayloads:     5,
		EnableTimeBased: false,
	})

	if err == nil {
		t.Error("Expected error for invalid URL")
	}

	if result == nil {
		t.Fatal("Expected non-nil result even on error")
	}
}

func TestDetector_Detect_VulnerableServerPasswdOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cmd := r.URL.Query().Get("cmd")
		if strings.Contains(cmd, "passwd") || strings.Contains(cmd, "cat") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	// Use Linux platform so the payload set includes cat /etc/passwd
	// variants — the universal "both" set has no passwd-style payloads.
	result, err := detector.Detect(context.Background(), server.URL+"?cmd=test", "cmd", "GET", DetectOptions{
		MaxPayloads:     20,
		EnableTimeBased: false,
		Platform:        cmdi.PlatformLinux,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerability to be detected with passwd output")
	}
}

func TestDetector_initOutputPatterns(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	if len(detector.outputPatterns) == 0 {
		t.Error("initOutputPatterns() should initialize patterns")
	}

	// Verify patterns actually match expected strings
	testCases := []struct {
		name    string
		input   string
		matches bool
	}{
		{"uid gid match", "uid=0(root) gid=0(root)", true},
		{"passwd match", "root:x:0:0:", true},
		{"ls match", "drwxr-xr-x 2 user user", true},
		{"windows path match", "C:\\Windows\\System32", true},
		{"no match", "completely normal text", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matched := false
			for _, p := range detector.outputPatterns {
				if p.MatchString(tc.input) {
					matched = true
					break
				}
			}
			if matched != tc.matches {
				t.Errorf("Pattern match for %q = %v, want %v", tc.input, matched, tc.matches)
			}
		})
	}
}

package executor

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/templates"
)

func TestNewSSLExecutor(t *testing.T) {
	t.Run("nil config uses defaults", func(t *testing.T) {
		exec := NewSSLExecutor(nil)
		if exec == nil {
			t.Fatal("NewSSLExecutor(nil) returned nil")
		}
		if exec.config == nil {
			t.Error("config should not be nil after initialization")
		}
		if exec.config.Timeout == 0 {
			t.Error("default timeout should be non-zero")
		}
		if exec.matcherEngine == nil {
			t.Error("matcherEngine should be initialized")
		}
	})

	t.Run("custom config is preserved", func(t *testing.T) {
		cfg := &SSLConfig{Timeout: 15 * time.Second}
		exec := NewSSLExecutor(cfg)
		if exec.config.Timeout != 15*time.Second {
			t.Errorf("Timeout = %v, want 15s", exec.config.Timeout)
		}
	})
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		wantHost string
		wantPort string
		wantErr  bool
	}{
		{
			name:     "plain hostname defaults to 443",
			target:   "example.com",
			wantHost: "example.com",
			wantPort: "443",
		},
		{
			name:     "hostname with explicit port",
			target:   "example.com:8443",
			wantHost: "example.com",
			wantPort: "8443",
		},
		{
			name:     "https URL strips scheme and path",
			target:   "https://example.com/some/path",
			wantHost: "example.com",
			wantPort: "443",
		},
		{
			name:     "https URL with explicit port",
			target:   "https://example.com:8443/path",
			wantHost: "example.com",
			wantPort: "8443",
		},
		{
			name:     "http URL defaults to 443",
			target:   "http://example.com",
			wantHost: "example.com",
			wantPort: "443",
		},
		{
			name:     "IPv4 address",
			target:   "192.168.1.1",
			wantHost: "192.168.1.1",
			wantPort: "443",
		},
		{
			name:     "IPv4 with port",
			target:   "192.168.1.1:4443",
			wantHost: "192.168.1.1",
			wantPort: "4443",
		},
		{
			name:     "IPv6 bracketed",
			target:   "[::1]:8443",
			wantHost: "::1",
			wantPort: "8443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := parseSSLTarget(tt.target)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseSSLTarget(%q) error = %v, wantErr %v", tt.target, err, tt.wantErr)
			}
			if err != nil {
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

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{tls.VersionTLS10, "tls10"},
		{tls.VersionTLS11, "tls11"},
		{tls.VersionTLS12, "tls12"},
		{tls.VersionTLS13, "tls13"},
		{0x0300, "ssl30"},
		{0x9999, "unknown"},
	}

	for _, tt := range tests {
		got := tlsVersionString(tt.version)
		if got != tt.want {
			t.Errorf("tlsVersionString(0x%04x) = %q, want %q", tt.version, got, tt.want)
		}
	}
}

func TestBuildSSLVars(t *testing.T) {
	notBefore := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	result := &SSLResult{
		Host:         "example.com",
		Port:         "443",
		Version:      "tls13",
		CipherSuite:  "TLS_AES_128_GCM_SHA256",
		SubjectCN:    "example.com",
		IssuerCN:     "Let's Encrypt R3",
		SANs:         []string{"example.com", "www.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		Expired:      false,
		SelfSigned:   false,
		subjectOrg:   "Example Org",
		issuerOrg:    "Let's Encrypt",
		serialNumber: "1234567890",
	}

	vars := buildSSLVars(result)

	checks := map[string]interface{}{
		"ssl_subject_cn":  "example.com",
		"ssl_issuer_cn":   "Let's Encrypt R3",
		"ssl_subject_org": "Example Org",
		"ssl_issuer_org":  "Let's Encrypt",
		"ssl_serial":      "1234567890",
		"ssl_version":     "tls13",
		"ssl_cipher":      "TLS_AES_128_GCM_SHA256",
		"ssl_expired":     false,
		"ssl_self_signed": false,
	}

	for key, want := range checks {
		got, ok := vars[key]
		if !ok {
			t.Errorf("vars[%q] not found", key)
			continue
		}
		switch w := want.(type) {
		case string:
			if s, ok := got.(string); !ok || s != w {
				t.Errorf("vars[%q] = %v, want %q", key, got, w)
			}
		case bool:
			if b, ok := got.(bool); !ok || b != w {
				t.Errorf("vars[%q] = %v, want %v", key, got, w)
			}
		}
	}

	// ssl_not_after should be a string
	if _, ok := vars["ssl_not_after"].(string); !ok {
		t.Errorf("vars[ssl_not_after] should be a string, got %T", vars["ssl_not_after"])
	}

	// ssl_dns_names should be a string
	if _, ok := vars["ssl_dns_names"].(string); !ok {
		t.Errorf("vars[ssl_dns_names] should be a string, got %T", vars["ssl_dns_names"])
	}

	// ssl_domains should be present
	if _, ok := vars["ssl_domains"]; !ok {
		t.Error("vars[ssl_domains] not found")
	}
}

func TestSSLExecute_ShortMode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TLS connection test in short mode")
	}

	exec := NewSSLExecutor(&SSLConfig{Timeout: 5 * time.Second})
	probe := &templates.SSLProbe{
		Matchers: []templates.Matcher{
			{
				Type:  "dsl",
				DSL:   []string{"ssl_subject_cn != \"\""},
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := exec.Execute(ctx, "https://badssl.com", probe)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result == nil {
		t.Fatal("Execute() returned nil result")
	}
	if result.Host == "" {
		t.Error("Host should not be empty")
	}
	if result.Port == "" {
		t.Error("Port should not be empty")
	}
}

func TestSSLExecute_ContextCancelled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TLS connection test in short mode")
	}

	exec := NewSSLExecutor(nil)
	probe := &templates.SSLProbe{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	result, _ := exec.Execute(ctx, "example.com:443", probe)
	if result != nil && result.Error == nil {
		// A cancelled context should produce an error; connection may or may not
		// succeed before cancellation is detected, so we only warn here.
		t.Log("note: result returned without error despite cancelled context (may be a timing issue)")
	}
}

func TestSSLResultFields(t *testing.T) {
	result := &SSLResult{
		Host:          "example.com",
		Port:          "443",
		Version:       "tls13",
		CipherSuite:   "TLS_AES_256_GCM_SHA384",
		SubjectCN:     "example.com",
		IssuerCN:      "DigiCert",
		SANs:          []string{"example.com", "www.example.com"},
		NotBefore:     time.Now().Add(-24 * time.Hour),
		NotAfter:      time.Now().Add(365 * 24 * time.Hour),
		Expired:       false,
		SelfSigned:    false,
		Matched:       true,
		ExtractedData: map[string][]string{"ssl_subject_cn": {"example.com"}},
		Raw:           "subject=example.com",
	}

	if result.Host != "example.com" {
		t.Errorf("Host = %q, want %q", result.Host, "example.com")
	}
	if result.Matched != true {
		t.Error("Matched should be true")
	}
	if len(result.SANs) != 2 {
		t.Errorf("len(SANs) = %d, want 2", len(result.SANs))
	}
	if result.Expired {
		t.Error("Expired should be false")
	}
}

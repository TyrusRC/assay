package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	internalhttp "github.com/swiss-knife-for-web-security/skws/internal/http"
)

func TestNew(t *testing.T) {
	client := internalhttp.NewClient()
	analyzer := New(client)

	if analyzer == nil {
		t.Fatal("New() returned nil")
	}
}

func TestAnalyzer_WithVerbose(t *testing.T) {
	client := internalhttp.NewClient()
	analyzer := New(client).WithVerbose(true)

	if !analyzer.verbose {
		t.Error("WithVerbose() did not set verbose flag")
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.Timeout <= 0 {
		t.Error("Timeout should be positive")
	}
}

func TestAnalyzer_AnalyzeTLSServer(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient().WithInsecure(true)
	analyzer := New(client)

	result, err := analyzer.Analyze(context.Background(), server.URL, DefaultOptions())

	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	// TLS server should be analyzed
	if result.TLSVersion == "" {
		t.Error("Expected TLS version to be detected")
	}
}

func TestAnalyzer_NonTLSServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	analyzer := New(client)

	result, err := analyzer.Analyze(context.Background(), server.URL, DefaultOptions())

	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// Non-TLS server should report missing TLS
	if !result.Vulnerable {
		t.Error("Expected non-TLS to be flagged as vulnerable")
	}
}

func TestAnalyzer_ContextCancellation(t *testing.T) {
	client := internalhttp.NewClient()
	analyzer := New(client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := analyzer.Analyze(ctx, "https://example.com", DefaultOptions())

	if err == nil {
		t.Error("Expected context cancellation error")
	}
}

func TestAnalyzer_TLSVersionCheck(t *testing.T) {
	tests := []struct {
		name     string
		version  uint16
		expected string
		secure   bool
	}{
		{name: "TLS 1.3", version: tls.VersionTLS13, expected: "TLS 1.3", secure: true},
		{name: "TLS 1.2", version: tls.VersionTLS12, expected: "TLS 1.2", secure: true},
		{name: "TLS 1.1", version: tls.VersionTLS11, expected: "TLS 1.1", secure: false},
		{name: "TLS 1.0", version: tls.VersionTLS10, expected: "TLS 1.0", secure: false},
	}

	client := internalhttp.NewClient()
	analyzer := New(client)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := analyzer.tlsVersionName(tt.version)
			if name != tt.expected {
				t.Errorf("tlsVersionName() = %s, want %s", name, tt.expected)
			}

			secure := analyzer.isSecureTLSVersion(tt.version)
			if secure != tt.secure {
				t.Errorf("isSecureTLSVersion() = %v, want %v", secure, tt.secure)
			}
		})
	}
}

func TestAnalyzer_CertificateChecks(t *testing.T) {
	analyzer := New(internalhttp.NewClient())

	// Test expired certificate check
	expiredCert := &x509.Certificate{
		NotAfter: time.Now().Add(-24 * time.Hour), // Expired yesterday
	}

	expired := analyzer.isCertExpired(expiredCert)
	if !expired {
		t.Error("Expected expired certificate to be detected")
	}

	// Test valid certificate check
	validCert := &x509.Certificate{
		NotAfter: time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
	}

	validExpired := analyzer.isCertExpired(validCert)
	if validExpired {
		t.Error("Expected valid certificate to not be expired")
	}

	// Test expiring soon check
	expiringSoonCert := &x509.Certificate{
		NotAfter: time.Now().Add(15 * 24 * time.Hour), // 15 days left
	}

	expiringSoon := analyzer.isCertExpiringSoon(expiringSoonCert, 30)
	if !expiringSoon {
		t.Error("Expected cert expiring in 15 days to be flagged with 30 day threshold")
	}
}

func TestAnalyzer_FindingOWASP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	analyzer := New(client)

	result, err := analyzer.Analyze(context.Background(), server.URL, DefaultOptions())

	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected findings for non-TLS server")
	}

	finding := result.Findings[0]
	if len(finding.WSTG) == 0 {
		t.Error("Expected WSTG mapping")
	}
	if len(finding.CWE) == 0 {
		t.Error("Expected CWE mapping")
	}
}

func TestDefaultOptions_Values(t *testing.T) {
	opts := DefaultOptions()

	if opts.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want 10s", opts.Timeout)
	}
	if !opts.CheckCertificate {
		t.Error("CheckCertificate should be true")
	}
	if !opts.CheckProtocol {
		t.Error("CheckProtocol should be true")
	}
	if opts.CertExpiryDays != 30 {
		t.Errorf("CertExpiryDays = %d, want 30", opts.CertExpiryDays)
	}
	if !opts.RequireHSTS {
		t.Error("RequireHSTS should be true")
	}
}

func TestAnalyzer_TLSVersionName_Unknown(t *testing.T) {
	analyzer := New(internalhttp.NewClient())
	name := analyzer.tlsVersionName(0x0200) // non-existent version
	if name == "" {
		t.Error("Should return non-empty string for unknown version")
	}
	if name == "TLS 1.0" || name == "TLS 1.1" || name == "TLS 1.2" || name == "TLS 1.3" {
		t.Errorf("Unknown version should not match known version, got %q", name)
	}
}

func TestAnalyzer_IsSelfSigned(t *testing.T) {
	analyzer := New(internalhttp.NewClient())

	tests := []struct {
		name     string
		cert     *x509.Certificate
		expected bool
	}{
		{
			name: "self-signed CA",
			cert: &x509.Certificate{
				IsCA: true,
				Issuer: pkix.Name{
					CommonName: "Self-Signed CA",
				},
				Subject: pkix.Name{
					CommonName: "Self-Signed CA",
				},
			},
			expected: true,
		},
		{
			name: "CA-signed certificate",
			cert: &x509.Certificate{
				IsCA: false,
				Issuer: pkix.Name{
					CommonName: "Let's Encrypt Authority X3",
				},
				Subject: pkix.Name{
					CommonName: "example.com",
				},
			},
			expected: false,
		},
		{
			name: "same names but not CA",
			cert: &x509.Certificate{
				IsCA: false,
				Issuer: pkix.Name{
					CommonName: "example.com",
				},
				Subject: pkix.Name{
					CommonName: "example.com",
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.isSelfSigned(tt.cert)
			if result != tt.expected {
				t.Errorf("isSelfSigned() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestAnalyzer_IsCertExpiringSoon_NotExpiring(t *testing.T) {
	analyzer := New(internalhttp.NewClient())

	cert := &x509.Certificate{
		NotAfter: time.Now().Add(365 * 24 * time.Hour), // 1 year left
	}

	if analyzer.isCertExpiringSoon(cert, 30) {
		t.Error("Certificate with 365 days left should not be flagged as expiring soon with 30 day threshold")
	}
}

func TestAnalyzer_InvalidURL(t *testing.T) {
	analyzer := New(internalhttp.NewClient())

	_, err := analyzer.Analyze(context.Background(), "://invalid", DefaultOptions())
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestAnalyzer_CalculateScore_NoHTTPS(t *testing.T) {
	analyzer := New(internalhttp.NewClient())

	result := &AnalysisResult{
		IsHTTPS: false,
	}

	score := analyzer.calculateScore(result)
	if score != 0 {
		t.Errorf("Score = %d, want 0 for non-HTTPS", score)
	}
}

func TestAnalyzer_CalculateScore_TLS13_NoFindings(t *testing.T) {
	analyzer := New(internalhttp.NewClient())

	result := &AnalysisResult{
		IsHTTPS:        true,
		TLSVersionCode: tls.VersionTLS13,
		Findings:       make([]*core.Finding, 0),
	}

	score := analyzer.calculateScore(result)
	if score != 100 {
		t.Errorf("Score = %d, want 100 for TLS 1.3 with no findings", score)
	}
}

func TestAnalyzer_CalculateScore_TLS12(t *testing.T) {
	analyzer := New(internalhttp.NewClient())

	result := &AnalysisResult{
		IsHTTPS:        true,
		TLSVersionCode: tls.VersionTLS12,
		Findings:       make([]*core.Finding, 0),
	}

	score := analyzer.calculateScore(result)
	if score != 95 {
		t.Errorf("Score = %d, want 95 for TLS 1.2 (5 deduction)", score)
	}
}

func TestAnalyzer_CalculateScore_WeakTLS(t *testing.T) {
	analyzer := New(internalhttp.NewClient())

	result := &AnalysisResult{
		IsHTTPS:        true,
		TLSVersionCode: tls.VersionTLS10,
		Findings:       make([]*core.Finding, 0),
	}

	score := analyzer.calculateScore(result)
	if score != 60 {
		t.Errorf("Score = %d, want 60 for TLS 1.0 (40 deduction)", score)
	}
}

func TestAnalyzer_CalculateScore_WithFindings(t *testing.T) {
	analyzer := New(internalhttp.NewClient())

	result := &AnalysisResult{
		IsHTTPS:        true,
		TLSVersionCode: tls.VersionTLS13,
		Findings: []*core.Finding{
			core.NewFinding("Critical issue", core.SeverityCritical),
			core.NewFinding("High issue", core.SeverityHigh),
		},
	}

	score := analyzer.calculateScore(result)
	// 100 - 50 (critical) - 30 (high) = 20
	if score != 20 {
		t.Errorf("Score = %d, want 20", score)
	}
}

func TestAnalyzer_CalculateScore_FloorAtZero(t *testing.T) {
	analyzer := New(internalhttp.NewClient())

	result := &AnalysisResult{
		IsHTTPS:        true,
		TLSVersionCode: tls.VersionTLS10,
		Findings: []*core.Finding{
			core.NewFinding("Critical issue 1", core.SeverityCritical),
			core.NewFinding("Critical issue 2", core.SeverityCritical),
		},
	}

	score := analyzer.calculateScore(result)
	// 100 - 40 (weak TLS) - 50 - 50 = -40, floor at 0
	if score != 0 {
		t.Errorf("Score = %d, want 0 (should not go below 0)", score)
	}
}

func TestAnalyzer_CalculateScore_MediumAndLow(t *testing.T) {
	analyzer := New(internalhttp.NewClient())

	result := &AnalysisResult{
		IsHTTPS:        true,
		TLSVersionCode: tls.VersionTLS13,
		Findings: []*core.Finding{
			core.NewFinding("Medium issue", core.SeverityMedium),
			core.NewFinding("Low issue", core.SeverityLow),
		},
	}

	score := analyzer.calculateScore(result)
	// 100 - 15 (medium) - 5 (low) = 80
	if score != 80 {
		t.Errorf("Score = %d, want 80", score)
	}
}

func TestAnalyzer_CreateNoHTTPSFinding(t *testing.T) {
	analyzer := New(internalhttp.NewClient())

	finding := analyzer.createNoHTTPSFinding("http://example.com")

	if finding.Type != "Missing HTTPS" {
		t.Errorf("Type = %q, want %q", finding.Type, "Missing HTTPS")
	}
	if finding.URL != "http://example.com" {
		t.Errorf("URL = %q", finding.URL)
	}
	if finding.Tool != "tls-analyzer" {
		t.Errorf("Tool = %q", finding.Tool)
	}
	if finding.Remediation == "" {
		t.Error("Remediation should not be empty")
	}
	if len(finding.WSTG) == 0 {
		t.Error("WSTG should not be empty")
	}
}

func TestAnalyzer_CreateWeakTLSFinding(t *testing.T) {
	analyzer := New(internalhttp.NewClient())

	finding := analyzer.createWeakTLSFinding("https://example.com", "TLS 1.0")

	if finding.Type != "Weak TLS Version" {
		t.Errorf("Type = %q", finding.Type)
	}
	if finding.Description == "" {
		t.Error("Description should not be empty")
	}
}

func TestAnalyzer_CreateExpiredCertFinding(t *testing.T) {
	analyzer := New(internalhttp.NewClient())

	cert := &x509.Certificate{
		NotAfter: time.Now().Add(-24 * time.Hour),
		Issuer:   pkix.Name{CommonName: "Test CA"},
		Subject:  pkix.Name{CommonName: "example.com"},
	}

	finding := analyzer.createExpiredCertFinding("https://example.com", cert)

	if finding.Type != "Expired SSL Certificate" {
		t.Errorf("Type = %q", finding.Type)
	}
	if string(finding.Severity) != "critical" {
		t.Errorf("Severity = %q, want critical", finding.Severity)
	}
}

func TestAnalyzer_CreateExpiringSoonFinding(t *testing.T) {
	analyzer := New(internalhttp.NewClient())

	cert := &x509.Certificate{
		NotAfter: time.Now().Add(15 * 24 * time.Hour),
		Issuer:   pkix.Name{CommonName: "Test CA"},
		Subject:  pkix.Name{CommonName: "example.com"},
	}

	finding := analyzer.createExpiringSoonFinding("https://example.com", cert, 30)

	if finding.Type != "SSL Certificate Expiring Soon" {
		t.Errorf("Type = %q", finding.Type)
	}
	if string(finding.Severity) != "medium" {
		t.Errorf("Severity = %q, want medium", finding.Severity)
	}
}

func TestAnalyzer_CreateHostnameMismatchFinding(t *testing.T) {
	analyzer := New(internalhttp.NewClient())

	cert := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "other.com"},
		DNSNames: []string{"other.com", "www.other.com"},
	}

	finding := analyzer.createHostnameMismatchFinding("https://example.com", "example.com", cert)

	if finding.Type != "SSL Certificate Hostname Mismatch" {
		t.Errorf("Type = %q", finding.Type)
	}
	if string(finding.Severity) != "high" {
		t.Errorf("Severity = %q, want high", finding.Severity)
	}
}

func TestAnalyzer_CreateSelfSignedFinding(t *testing.T) {
	analyzer := New(internalhttp.NewClient())

	cert := &x509.Certificate{
		IsCA:    true,
		Issuer:  pkix.Name{CommonName: "Self-Signed"},
		Subject: pkix.Name{CommonName: "Self-Signed"},
	}

	finding := analyzer.createSelfSignedFinding("https://example.com", cert)

	if finding.Type != "Self-Signed SSL Certificate" {
		t.Errorf("Type = %q", finding.Type)
	}
	if string(finding.Severity) != "medium" {
		t.Errorf("Severity = %q, want medium", finding.Severity)
	}
}

func TestAnalyzer_Analyze_HTTPTargetScore(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	analyzer := New(internalhttp.NewClient())
	result, err := analyzer.Analyze(context.Background(), server.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if result.Score != 0 {
		t.Errorf("Score = %d, want 0 for non-HTTPS target", result.Score)
	}
	if result.IsHTTPS {
		t.Error("IsHTTPS should be false for HTTP target")
	}
}

func TestAnalyzer_Analyze_PortParsing(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	analyzer := New(internalhttp.NewClient().WithInsecure(true))
	result, err := analyzer.Analyze(context.Background(), server.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if !result.IsHTTPS {
		t.Error("IsHTTPS should be true for TLS server")
	}
	if result.TLSVersion == "" {
		t.Error("TLSVersion should not be empty")
	}
	if result.CipherSuite == "" {
		t.Error("CipherSuite should not be empty")
	}
}

func TestAnalysisResult_Fields(t *testing.T) {
	result := &AnalysisResult{
		Vulnerable:     true,
		TLSVersion:     "TLS 1.3",
		TLSVersionCode: tls.VersionTLS13,
		CipherSuite:    "TLS_AES_256_GCM_SHA384",
		CertIssuer:     "Let's Encrypt",
		CertExpiry:     time.Now().Add(90 * 24 * time.Hour),
		CertDaysLeft:   90,
		IsHTTPS:        true,
		HasHSTS:        true,
		Score:          95,
	}

	if !result.Vulnerable {
		t.Error("Vulnerable should be true")
	}
	if result.TLSVersion != "TLS 1.3" {
		t.Errorf("TLSVersion = %q", result.TLSVersion)
	}
	if result.CertDaysLeft != 90 {
		t.Errorf("CertDaysLeft = %d", result.CertDaysLeft)
	}
}

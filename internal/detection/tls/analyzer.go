// Package tls provides SSL/TLS configuration analysis and vulnerability detection.
package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

// Analyzer performs SSL/TLS configuration analysis.
type Analyzer struct {
	client  *http.Client
	verbose bool
}

// New creates a new TLS Analyzer.
func New(client *http.Client) *Analyzer {
	return &Analyzer{
		client: client,
	}
}

// WithVerbose enables verbose output.
func (a *Analyzer) WithVerbose(verbose bool) *Analyzer {
	a.verbose = verbose
	return a
}

// AnalyzeOptions configures TLS analysis behavior.
type AnalyzeOptions struct {
	Timeout          time.Duration
	CheckCertificate bool
	CheckProtocol    bool
	CertExpiryDays   int // Warn if cert expires within N days
	RequireHSTS      bool
}

// DefaultOptions returns default analysis options.
func DefaultOptions() AnalyzeOptions {
	return AnalyzeOptions{
		Timeout:          10 * time.Second,
		CheckCertificate: true,
		CheckProtocol:    true,
		CertExpiryDays:   30,
		RequireHSTS:      true,
	}
}

// AnalysisResult contains TLS analysis results.
type AnalysisResult struct {
	Vulnerable     bool
	Findings       []*core.Finding
	TLSVersion     string
	TLSVersionCode uint16
	CipherSuite    string
	CertIssuer     string
	CertExpiry     time.Time
	CertDaysLeft   int
	IsHTTPS        bool
	HasHSTS        bool
	Score          int
}

// Analyze performs TLS analysis on a target.
func (a *Analyzer) Analyze(ctx context.Context, target string, opts AnalyzeOptions) (*AnalysisResult, error) {
	result := &AnalysisResult{
		Findings: make([]*core.Finding, 0),
	}

	// Check context
	select {
	case <-ctx.Done():
		return result, ctx.Err()
	default:
	}

	// Parse target URL
	parsedURL, err := url.Parse(target)
	if err != nil {
		return result, fmt.Errorf("invalid target URL: %w", err)
	}

	// Check if target uses HTTPS
	if parsedURL.Scheme != "https" {
		result.IsHTTPS = false
		result.Vulnerable = true
		finding := a.createNoHTTPSFinding(target)
		result.Findings = append(result.Findings, finding)
		result.Score = 0
		return result, nil
	}

	result.IsHTTPS = true

	// Get host and port
	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		port = "443"
	}

	// Perform TLS handshake
	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: opts.Timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return result, fmt.Errorf("TLS connection failed: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	result.TLSVersionCode = state.Version
	result.TLSVersion = a.tlsVersionName(state.Version)
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	// Check TLS version
	if opts.CheckProtocol && !a.isSecureTLSVersion(state.Version) {
		finding := a.createWeakTLSFinding(target, result.TLSVersion)
		result.Findings = append(result.Findings, finding)
		result.Vulnerable = true
	}

	// Analyze certificates
	if opts.CheckCertificate && len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.CertExpiry = cert.NotAfter
		result.CertDaysLeft = int(time.Until(cert.NotAfter).Hours() / 24)
		result.CertIssuer = cert.Issuer.CommonName

		// Check if certificate is expired
		if a.isCertExpired(cert) {
			finding := a.createExpiredCertFinding(target, cert)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
		} else if a.isCertExpiringSoon(cert, opts.CertExpiryDays) {
			finding := a.createExpiringSoonFinding(target, cert, opts.CertExpiryDays)
			result.Findings = append(result.Findings, finding)
		}

		// Check hostname verification
		if err := cert.VerifyHostname(host); err != nil {
			finding := a.createHostnameMismatchFinding(target, host, cert)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
		}

		// Check for self-signed certificate
		if a.isSelfSigned(cert) {
			finding := a.createSelfSignedFinding(target, cert)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
		}
	}

	// Calculate score
	result.Score = a.calculateScore(result)

	return result, nil
}

// tlsVersionName returns the human-readable name of a TLS version.
func (a *Analyzer) tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// isSecureTLSVersion checks if the TLS version is considered secure.
func (a *Analyzer) isSecureTLSVersion(version uint16) bool {
	return version >= tls.VersionTLS12
}

// isCertExpired checks if a certificate is expired.
func (a *Analyzer) isCertExpired(cert *x509.Certificate) bool {
	return time.Now().After(cert.NotAfter)
}

// isCertExpiringSoon checks if a certificate expires within the threshold.
func (a *Analyzer) isCertExpiringSoon(cert *x509.Certificate, days int) bool {
	threshold := time.Now().Add(time.Duration(days) * 24 * time.Hour)
	return cert.NotAfter.Before(threshold)
}

// isSelfSigned checks if a certificate is self-signed.
func (a *Analyzer) isSelfSigned(cert *x509.Certificate) bool {
	return cert.IsCA && cert.Issuer.CommonName == cert.Subject.CommonName
}

// createNoHTTPSFinding creates a finding for non-HTTPS targets.
func (a *Analyzer) createNoHTTPSFinding(target string) *core.Finding {
	finding := core.NewFinding("Missing HTTPS", core.SeverityHigh)
	finding.URL = target
	finding.Description = "The target does not use HTTPS encryption. " +
		"All data transmitted between the client and server is sent in plaintext, " +
		"making it vulnerable to eavesdropping and man-in-the-middle attacks."
	finding.Evidence = fmt.Sprintf("URL scheme: %s (not https)", strings.Split(target, "://")[0])
	finding.Tool = "tls-analyzer"
	finding.Confidence = core.ConfidenceConfirmed
	finding.Remediation = "Enable HTTPS by obtaining and installing an SSL/TLS certificate. " +
		"Use Let's Encrypt for free certificates. " +
		"Redirect all HTTP traffic to HTTPS. " +
		"Enable HSTS headers."

	finding.WithOWASPMapping(
		[]string{"WSTG-CRYP-01"}, // Testing for Weak Transport Layer Security
		[]string{"A02:2021"},     // Cryptographic Failures
		[]string{"CWE-319"},      // Cleartext Transmission of Sensitive Information
	)

	return finding
}

// createWeakTLSFinding creates a finding for weak TLS versions.
func (a *Analyzer) createWeakTLSFinding(target, version string) *core.Finding {
	finding := core.NewFinding("Weak TLS Version", core.SeverityHigh)
	finding.URL = target
	finding.Description = fmt.Sprintf(
		"The server supports %s, which is deprecated and has known vulnerabilities. "+
			"TLS 1.0 and 1.1 are susceptible to BEAST, POODLE, and other attacks.",
		version,
	)
	finding.Evidence = fmt.Sprintf("Negotiated TLS version: %s", version)
	finding.Tool = "tls-analyzer"
	finding.Confidence = core.ConfidenceConfirmed
	finding.Remediation = "Disable TLS 1.0 and TLS 1.1 support. " +
		"Configure the server to use TLS 1.2 or TLS 1.3 only. " +
		"Update server software if necessary."

	finding.WithOWASPMapping(
		[]string{"WSTG-CRYP-01"},
		[]string{"A02:2021"},
		[]string{"CWE-326"}, // Inadequate Encryption Strength
	)

	return finding
}

// createExpiredCertFinding creates a finding for expired certificates.
func (a *Analyzer) createExpiredCertFinding(target string, cert *x509.Certificate) *core.Finding {
	finding := core.NewFinding("Expired SSL Certificate", core.SeverityCritical)
	finding.URL = target
	finding.Description = fmt.Sprintf(
		"The SSL/TLS certificate expired on %s. "+
			"Expired certificates cause browser warnings and break trust.",
		cert.NotAfter.Format("2006-01-02"),
	)
	finding.Evidence = fmt.Sprintf("Certificate expiry: %s\nIssuer: %s\nSubject: %s",
		cert.NotAfter.Format(time.RFC3339), cert.Issuer.CommonName, cert.Subject.CommonName)
	finding.Tool = "tls-analyzer"
	finding.Confidence = core.ConfidenceConfirmed
	finding.Remediation = "Renew the SSL/TLS certificate immediately. " +
		"Set up automatic certificate renewal using ACME/Let's Encrypt. " +
		"Implement certificate expiry monitoring."

	finding.WithOWASPMapping(
		[]string{"WSTG-CRYP-01"},
		[]string{"A02:2021"},
		[]string{"CWE-295"}, // Improper Certificate Validation
	)

	return finding
}

// createExpiringSoonFinding creates a finding for certificates expiring soon.
func (a *Analyzer) createExpiringSoonFinding(target string, cert *x509.Certificate, days int) *core.Finding {
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)

	finding := core.NewFinding("SSL Certificate Expiring Soon", core.SeverityMedium)
	finding.URL = target
	finding.Description = fmt.Sprintf(
		"The SSL/TLS certificate expires in %d days (on %s). "+
			"Renew before expiration to prevent service disruption.",
		daysLeft, cert.NotAfter.Format("2006-01-02"),
	)
	finding.Evidence = fmt.Sprintf("Certificate expiry: %s\nDays remaining: %d\nThreshold: %d days",
		cert.NotAfter.Format(time.RFC3339), daysLeft, days)
	finding.Tool = "tls-analyzer"
	finding.Confidence = core.ConfidenceConfirmed
	finding.Remediation = "Renew the SSL/TLS certificate before expiration. " +
		"Set up automatic certificate renewal."

	finding.WithOWASPMapping(
		[]string{"WSTG-CRYP-01"},
		[]string{"A02:2021"},
		[]string{"CWE-298"}, // Improper Validation of Certificate Expiration
	)

	return finding
}

// createHostnameMismatchFinding creates a finding for hostname mismatch.
func (a *Analyzer) createHostnameMismatchFinding(target, host string, cert *x509.Certificate) *core.Finding {
	finding := core.NewFinding("SSL Certificate Hostname Mismatch", core.SeverityHigh)
	finding.URL = target
	finding.Description = fmt.Sprintf(
		"The SSL/TLS certificate does not match the hostname '%s'. "+
			"This causes browser warnings and indicates potential misconfiguration.",
		host,
	)
	finding.Evidence = fmt.Sprintf("Expected hostname: %s\nCertificate subject: %s\nDNS names: %v",
		host, cert.Subject.CommonName, cert.DNSNames)
	finding.Tool = "tls-analyzer"
	finding.Confidence = core.ConfidenceConfirmed
	finding.Remediation = "Obtain a certificate that includes the correct hostname. " +
		"Use Subject Alternative Names (SAN) for multiple hostnames."

	finding.WithOWASPMapping(
		[]string{"WSTG-CRYP-01"},
		[]string{"A02:2021"},
		[]string{"CWE-295"},
	)

	return finding
}

// createSelfSignedFinding creates a finding for self-signed certificates.
func (a *Analyzer) createSelfSignedFinding(target string, cert *x509.Certificate) *core.Finding {
	finding := core.NewFinding("Self-Signed SSL Certificate", core.SeverityMedium)
	finding.URL = target
	finding.Description = "The server uses a self-signed SSL/TLS certificate. " +
		"Self-signed certificates are not trusted by browsers and " +
		"provide no assurance of the server's identity."
	finding.Evidence = fmt.Sprintf("Issuer: %s\nSubject: %s (self-signed)",
		cert.Issuer.CommonName, cert.Subject.CommonName)
	finding.Tool = "tls-analyzer"
	finding.Confidence = core.ConfidenceConfirmed
	finding.Remediation = "Replace the self-signed certificate with one issued by a trusted CA. " +
		"Use Let's Encrypt for free trusted certificates."

	finding.WithOWASPMapping(
		[]string{"WSTG-CRYP-01"},
		[]string{"A02:2021"},
		[]string{"CWE-295"},
	)

	return finding
}

// calculateScore calculates a TLS security score (0-100).
func (a *Analyzer) calculateScore(result *AnalysisResult) int {
	if !result.IsHTTPS {
		return 0
	}

	score := 100

	// Deduct for weak TLS version
	if result.TLSVersionCode < tls.VersionTLS12 {
		score -= 40
	} else if result.TLSVersionCode == tls.VersionTLS12 {
		score -= 5 // Minor deduction, TLS 1.2 is still acceptable
	}

	// Deduct for findings
	for _, f := range result.Findings {
		switch f.Severity {
		case core.SeverityCritical:
			score -= 50
		case core.SeverityHigh:
			score -= 30
		case core.SeverityMedium:
			score -= 15
		case core.SeverityLow:
			score -= 5
		}
	}

	if score < 0 {
		score = 0
	}

	return score
}

package executor

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates/matchers"
)

// SSLConfig configures the SSL executor behavior.
type SSLConfig struct {
	// Timeout for establishing TLS connections.
	Timeout time.Duration

	// ProxyURL routes TLS connections through an HTTP CONNECT proxy (e.g. http://127.0.0.1:8080 for Burp Suite).
	ProxyURL string
}

// DefaultSSLConfig returns sensible defaults for SSL scanning.
func DefaultSSLConfig() *SSLConfig {
	return &SSLConfig{
		Timeout: 10 * time.Second,
	}
}

// SSLExecutor executes SSL/TLS probes defined in templates.
type SSLExecutor struct {
	matcherEngine *matchers.MatcherEngine
	config        *SSLConfig
}

// SSLResult contains the outcome of an SSL/TLS probe execution.
type SSLResult struct {
	// Host that was connected to.
	Host string

	// Port that was connected to.
	Port string

	// Negotiated TLS version string (e.g. "tls13").
	Version string

	// Negotiated cipher suite name.
	CipherSuite string

	// Subject common name from the leaf certificate.
	SubjectCN string

	// Issuer common name from the leaf certificate.
	IssuerCN string

	// Subject alternative names from the leaf certificate.
	SANs []string

	// Certificate validity window.
	NotBefore time.Time
	NotAfter  time.Time

	// Expired is true when the current time is after NotAfter.
	Expired bool

	// SelfSigned is true when the issuer equals the subject.
	SelfSigned bool

	// Matched is true when at least one matcher matched.
	Matched bool

	// ExtractedData holds values collected by extractors.
	ExtractedData map[string][]string

	// Raw is a text representation of the certificate for word/regex matching.
	Raw string

	// Error holds any error encountered during the probe.
	Error error

	// unexported fields for DSL vars only – not part of the public API
	subjectOrg   string
	issuerOrg    string
	serialNumber string
}

// NewSSLExecutor creates a new SSL executor, applying defaults for nil config.
func NewSSLExecutor(config *SSLConfig) *SSLExecutor {
	if config == nil {
		config = DefaultSSLConfig()
	}
	if config.Timeout == 0 {
		config.Timeout = DefaultSSLConfig().Timeout
	}
	return &SSLExecutor{
		matcherEngine: matchers.New(),
		config:        config,
	}
}

// Execute connects to target via TLS, extracts certificate information, and
// evaluates the matchers and extractors in probe.
func (e *SSLExecutor) Execute(ctx context.Context, target string, probe *templates.SSLProbe) (*SSLResult, error) {
	result := &SSLResult{
		ExtractedData: make(map[string][]string),
	}

	host, port, err := parseSSLTarget(target)
	if err != nil {
		result.Error = fmt.Errorf("parse target: %w", err)
		return result, result.Error
	}

	result.Host = host
	result.Port = port

	tlsConn, err := e.dialTLS(ctx, host, port)
	if err != nil {
		result.Error = fmt.Errorf("tls dial %s:%s: %w", host, port, err)
		return result, nil // connection failure is a valid probe result
	}
	defer tlsConn.Close()
	conn := tlsConn

	// Verify the context has not been cancelled after connect.
	select {
	case <-ctx.Done():
		result.Error = ctx.Err()
		return result, ctx.Err()
	default:
	}

	cs := conn.ConnectionState()

	result.Version = tlsVersionString(cs.Version)
	result.CipherSuite = tls.CipherSuiteName(cs.CipherSuite)

	// Extract information from the leaf (peer) certificate.
	if len(cs.PeerCertificates) > 0 {
		leaf := cs.PeerCertificates[0]

		result.SubjectCN = leaf.Subject.CommonName
		result.IssuerCN = leaf.Issuer.CommonName
		result.SANs = leaf.DNSNames
		result.NotBefore = leaf.NotBefore
		result.NotAfter = leaf.NotAfter
		result.Expired = time.Now().After(leaf.NotAfter)
		result.SelfSigned = leaf.Subject.String() == leaf.Issuer.String()

		result.subjectOrg = strings.Join(leaf.Subject.Organization, ",")
		result.issuerOrg = strings.Join(leaf.Issuer.Organization, ",")
		result.serialNumber = leaf.SerialNumber.String()
	}

	// Build raw text representation for word / regex matching.
	result.Raw = buildSSLRaw(result)

	// Build DSL variable context.
	vars := buildSSLVars(result)

	// Build the matcher response (body = raw cert text).
	matcherResp := &matchers.Response{
		Body: result.Raw,
		Raw:  result.Raw,
	}

	// Evaluate matchers.
	matched, extracts := e.matcherEngine.MatchAll(probe.Matchers, "", matcherResp, vars)
	result.Matched = matched
	for k, v := range extracts {
		result.ExtractedData[k] = v
	}

	// Run extractors.
	extracted := e.runSSLExtractors(probe.Extractors, matcherResp, vars)
	for k, v := range extracted {
		result.ExtractedData[k] = v
	}

	return result, nil
}

// dialTLS establishes a TLS connection to host:port, optionally tunnelling
// through an HTTP CONNECT proxy when SSLConfig.ProxyURL is set.
func (e *SSLExecutor) dialTLS(ctx context.Context, host, port string) (*tls.Conn, error) {
	addr := net.JoinHostPort(host, port)
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // intentional for certificate inspection
		ServerName:         host,
	}

	if e.config.ProxyURL != "" {
		proxyURL, err := url.Parse(e.config.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}

		proxyAddr := proxyURL.Host
		if !strings.Contains(proxyAddr, ":") {
			proxyAddr += ":8080"
		}

		dialer := &net.Dialer{Timeout: e.config.Timeout}
		proxyConn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
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

		tlsConn := tls.Client(proxyConn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			proxyConn.Close()
			return nil, fmt.Errorf("TLS handshake via proxy failed: %w", err)
		}
		return tlsConn, nil
	}

	// Direct connection (no proxy).
	dialer := &net.Dialer{Timeout: e.config.Timeout}
	return tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
}

// parseSSLTarget parses a target string and returns the host and port.
// It accepts bare hostnames, host:port pairs, and full URLs.
// The default port when none is specified is 443.
func parseSSLTarget(target string) (host, port string, err error) {
	// Normalise: if no scheme is present but a colon+digit pair that looks like
	// a port exists, treat as host:port; otherwise wrap with https:// so
	// url.Parse can handle it.
	if !strings.Contains(target, "://") {
		// Check for bare IPv6 bracketed address or host:port.
		if _, _, splitErr := net.SplitHostPort(target); splitErr == nil {
			// It is already a host:port pair.
			host, port, err = net.SplitHostPort(target)
			if err != nil {
				return "", "", fmt.Errorf("split host/port: %w", err)
			}
			if port == "" {
				port = "443"
			}
			return host, port, nil
		}
		// Plain hostname – wrap.
		target = "https://" + target
	}

	parsed, err := url.Parse(target)
	if err != nil {
		return "", "", fmt.Errorf("parse url: %w", err)
	}

	host = parsed.Hostname()
	port = parsed.Port()
	if port == "" {
		port = "443"
	}

	return host, port, nil
}

// tlsVersionString converts a TLS version constant to a short name used in DSL.
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "tls10"
	case tls.VersionTLS11:
		return "tls11"
	case tls.VersionTLS12:
		return "tls12"
	case tls.VersionTLS13:
		return "tls13"
	case 0x0300:
		return "ssl30"
	default:
		return "unknown"
	}
}

// buildSSLVars builds the DSL variable map from an SSLResult.
func buildSSLVars(r *SSLResult) map[string]interface{} {
	dnsNames := strings.Join(r.SANs, ",")
	domains := r.SubjectCN
	if len(r.SANs) > 0 {
		domains = strings.Join(r.SANs, ",")
	}

	return map[string]interface{}{
		"ssl_subject_cn":  r.SubjectCN,
		"ssl_issuer_cn":   r.IssuerCN,
		"ssl_subject_org": r.subjectOrg,
		"ssl_issuer_org":  r.issuerOrg,
		"ssl_not_after":   r.NotAfter.Format(time.RFC3339),
		"ssl_not_before":  r.NotBefore.Format(time.RFC3339),
		"ssl_expired":     r.Expired,
		"ssl_self_signed": r.SelfSigned,
		"ssl_serial":      r.serialNumber,
		"ssl_dns_names":   dnsNames,
		"ssl_version":     r.Version,
		"ssl_cipher":      r.CipherSuite,
		"ssl_domains":     domains,
	}
}

// buildSSLRaw builds a plain-text representation of the certificate for
// word and regex matching.
func buildSSLRaw(r *SSLResult) string {
	var sb strings.Builder
	sb.WriteString("subject_cn=" + r.SubjectCN + "\n")
	sb.WriteString("issuer_cn=" + r.IssuerCN + "\n")
	sb.WriteString("subject_org=" + r.subjectOrg + "\n")
	sb.WriteString("issuer_org=" + r.issuerOrg + "\n")
	sb.WriteString("not_before=" + r.NotBefore.Format(time.RFC3339) + "\n")
	sb.WriteString("not_after=" + r.NotAfter.Format(time.RFC3339) + "\n")
	sb.WriteString(fmt.Sprintf("expired=%v\n", r.Expired))
	sb.WriteString(fmt.Sprintf("self_signed=%v\n", r.SelfSigned))
	sb.WriteString("serial=" + r.serialNumber + "\n")
	sb.WriteString("dns_names=" + strings.Join(r.SANs, ",") + "\n")
	sb.WriteString("version=" + r.Version + "\n")
	sb.WriteString("cipher=" + r.CipherSuite + "\n")
	return sb.String()
}

// runSSLExtractors evaluates extractors against the SSL response and variables.
func (e *SSLExecutor) runSSLExtractors(
	extractors []templates.Extractor,
	resp *matchers.Response,
	vars map[string]interface{},
) map[string][]string {
	result := make(map[string][]string)
	dslEngine := matchers.NewDSLEngine()

	for _, ext := range extractors {
		if ext.Internal {
			continue
		}

		var extracted []string
		content := resp.Body

		switch ext.Type {
		case "regex":
			extracted = extractRegex(ext.Regex, content, ext.Group)
		case "json":
			extracted = extractJSON(ext.JSON, content)
		case "dsl":
			extracted = extractDSL(dslEngine, ext.DSL, vars)
		}

		if len(extracted) > 0 && ext.Name != "" {
			result[ext.Name] = extracted
		}
	}

	return result
}

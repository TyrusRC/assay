// Package executor provides template execution capabilities.
package executor

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates/matchers"
)

// DNSConfig configures DNS executor behavior.
type DNSConfig struct {
	// Timeout for DNS queries.
	Timeout time.Duration

	// Number of retry attempts for failed queries.
	Retries int

	// Nameserver to use for queries (host:port format).
	Nameserver string

	// Use TCP instead of UDP.
	UseTCP bool

	// Note: DNS queries do not support HTTP proxy forwarding because the DNS
	// protocol communicates over UDP (or TCP directly) rather than HTTP/CONNECT.
	// To route DNS through a proxy-like mechanism, configure a custom Nameserver
	// that is reachable via the desired network path.
}

// DefaultDNSConfig returns sensible defaults.
func DefaultDNSConfig() *DNSConfig {
	return &DNSConfig{
		Timeout:    5 * time.Second,
		Retries:    2,
		Nameserver: "", // Will use system resolver
	}
}

// DNSExecutor executes DNS-based template queries.
type DNSExecutor struct {
	client        *dns.Client
	matcherEngine *matchers.MatcherEngine
	config        *DNSConfig
}

// DNSRecord represents a single DNS record.
type DNSRecord struct {
	Type  string
	Value string
	TTL   uint32
	Name  string
}

// DNSResult contains the result of a DNS query execution.
type DNSResult struct {
	// Query name that was resolved.
	Query string

	// Query type (A, AAAA, MX, etc.).
	Type string

	// Resolver used for the query.
	Resolver string

	// Records returned by the query.
	Records []DNSRecord

	// Raw response string for matching.
	Raw string

	// Whether matchers matched.
	Matched bool

	// Extracted data from extractors.
	ExtractedData map[string][]string

	// Response code.
	Rcode int

	// Response code string.
	RcodeString string

	// Error if query failed.
	Error error
}

// NewDNSExecutor creates a new DNS executor.
func NewDNSExecutor(config *DNSConfig) *DNSExecutor {
	if config == nil {
		config = DefaultDNSConfig()
	}

	client := &dns.Client{
		Timeout: config.Timeout,
	}

	if config.UseTCP {
		client.Net = "tcp"
	}

	return &DNSExecutor{
		client:        client,
		matcherEngine: matchers.New(),
		config:        config,
	}
}

// Execute runs a DNS query against a target.
func (e *DNSExecutor) Execute(ctx context.Context, target string, query *templates.DNSQuery) (*DNSResult, error) {
	result := &DNSResult{
		Type:          query.Type,
		ExtractedData: make(map[string][]string),
	}

	// Build variables for interpolation
	vars := e.buildVariables(target)

	// Interpolate query name
	queryName := e.interpolate(query.Name, vars)
	if queryName == "" {
		queryName = target
	}

	// Ensure query name ends with dot
	if !strings.HasSuffix(queryName, ".") {
		queryName = queryName + "."
	}
	result.Query = strings.TrimSuffix(queryName, ".")

	// Determine nameserver
	nameserver := e.config.Nameserver
	if nameserver == "" {
		nameserver = getSystemResolver()
	}
	result.Resolver = nameserver

	// Build DNS message
	msg := new(dns.Msg)
	msg.SetQuestion(queryName, dnsQueryType(query.Type))
	msg.RecursionDesired = true // Recursion is always enabled for security scanning

	// Set query class
	if query.Class != "" {
		msg.Question[0].Qclass = dnsQueryClass(query.Class)
	}

	// Determine retries
	retries := e.config.Retries
	if query.Retries > 0 {
		retries = query.Retries
	}

	// Execute query with retries
	var resp *dns.Msg
	var err error
	for attempt := 0; attempt <= retries; attempt++ {
		select {
		case <-ctx.Done():
			result.Error = ctx.Err()
			return result, ctx.Err()
		default:
		}

		resp, _, err = e.client.ExchangeContext(ctx, msg, nameserver)
		if err == nil {
			break
		}

		// Check if context is cancelled
		if ctx.Err() != nil {
			result.Error = ctx.Err()
			return result, ctx.Err()
		}

		// Wait before retry
		if attempt < retries {
			select {
			case <-ctx.Done():
				result.Error = ctx.Err()
				return result, ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
	}

	if err != nil {
		result.Error = fmt.Errorf("dns query failed: %w", err)
		return result, err
	}

	// Parse response
	result.Rcode = resp.Rcode
	result.RcodeString = dns.RcodeToString[resp.Rcode]
	result.Records = formatDNSRecords(resp.Answer)
	result.Raw = buildDNSRaw(resp)

	// Build matcher response
	matcherResp := &matchers.Response{
		Body: result.Raw,
		Raw:  result.Raw,
	}

	// Evaluate matchers
	matched, extracts := e.matcherEngine.MatchAll(
		query.Matchers,
		"", // Default to OR
		matcherResp,
		vars,
	)
	result.Matched = matched
	for k, v := range extracts {
		result.ExtractedData[k] = v
	}

	// Run extractors
	extracted := e.runExtractors(query.Extractors, matcherResp, vars)
	for k, v := range extracted {
		result.ExtractedData[k] = v
	}

	return result, nil
}

// buildVariables builds variable context for interpolation.
func (e *DNSExecutor) buildVariables(target string) map[string]interface{} {
	vars := make(map[string]interface{})

	// Parse target to extract hostname
	hostname := target
	if strings.Contains(target, "://") {
		parts := strings.SplitN(target, "://", 2)
		if len(parts) > 1 {
			hostname = parts[1]
		}
	}

	// Remove port if present
	if h, _, err := net.SplitHostPort(hostname); err == nil {
		hostname = h
	}

	vars["Hostname"] = hostname
	vars["Host"] = hostname
	vars["FQDN"] = hostname

	return vars
}

// interpolate replaces template variables in a string.
func (e *DNSExecutor) interpolate(s string, vars map[string]interface{}) string {
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
func (e *DNSExecutor) runExtractors(extractors []templates.Extractor, resp *matchers.Response, vars map[string]interface{}) map[string][]string {
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
			// Not applicable for DNS
		case "json":
			// Not applicable for DNS
		}

		if len(extracted) > 0 && ext.Name != "" {
			result[ext.Name] = extracted
		}
	}

	return result
}

// dnsQueryType converts a string query type to dns package constant.
func dnsQueryType(qtype string) uint16 {
	switch strings.ToUpper(qtype) {
	case "A":
		return dns.TypeA
	case "AAAA":
		return dns.TypeAAAA
	case "MX":
		return dns.TypeMX
	case "TXT":
		return dns.TypeTXT
	case "NS":
		return dns.TypeNS
	case "CNAME":
		return dns.TypeCNAME
	case "SOA":
		return dns.TypeSOA
	case "PTR":
		return dns.TypePTR
	case "SRV":
		return dns.TypeSRV
	case "CAA":
		return dns.TypeCAA
	case "ANY":
		return dns.TypeANY
	default:
		return dns.TypeA
	}
}

// dnsQueryClass converts a string class to dns package constant.
func dnsQueryClass(class string) uint16 {
	switch strings.ToUpper(class) {
	case "IN", "INET":
		return dns.ClassINET
	case "CH", "CHAOS":
		return dns.ClassCHAOS
	case "HS", "HESIOD":
		return dns.ClassHESIOD
	case "ANY":
		return dns.ClassANY
	default:
		return dns.ClassINET
	}
}

// formatDNSRecords converts dns.RR records to DNSRecord slice.
func formatDNSRecords(records []dns.RR) []DNSRecord {
	result := make([]DNSRecord, 0, len(records))

	for _, rr := range records {
		record := DNSRecord{
			Name: rr.Header().Name,
			TTL:  rr.Header().Ttl,
		}

		switch r := rr.(type) {
		case *dns.A:
			record.Type = "A"
			record.Value = r.A.String()
		case *dns.AAAA:
			record.Type = "AAAA"
			record.Value = r.AAAA.String()
		case *dns.MX:
			record.Type = "MX"
			record.Value = fmt.Sprintf("%d %s", r.Preference, r.Mx)
		case *dns.TXT:
			record.Type = "TXT"
			record.Value = strings.Join(r.Txt, " ")
		case *dns.NS:
			record.Type = "NS"
			record.Value = r.Ns
		case *dns.CNAME:
			record.Type = "CNAME"
			record.Value = r.Target
		case *dns.SOA:
			record.Type = "SOA"
			record.Value = fmt.Sprintf("%s %s %d %d %d %d %d",
				r.Ns, r.Mbox, r.Serial, r.Refresh, r.Retry, r.Expire, r.Minttl)
		case *dns.PTR:
			record.Type = "PTR"
			record.Value = r.Ptr
		case *dns.SRV:
			record.Type = "SRV"
			record.Value = fmt.Sprintf("%d %d %d %s",
				r.Priority, r.Weight, r.Port, r.Target)
		case *dns.CAA:
			record.Type = "CAA"
			record.Value = fmt.Sprintf("%d %s %s", r.Flag, r.Tag, r.Value)
		default:
			record.Type = dns.TypeToString[rr.Header().Rrtype]
			record.Value = rr.String()
		}

		result = append(result, record)
	}

	return result
}

// buildDNSRaw builds a raw string representation of the DNS response.
func buildDNSRaw(resp *dns.Msg) string {
	var sb strings.Builder

	// Add answer section
	for _, rr := range resp.Answer {
		sb.WriteString(rr.String())
		sb.WriteString("\n")
	}

	// Add authority section
	for _, rr := range resp.Ns {
		sb.WriteString(rr.String())
		sb.WriteString("\n")
	}

	// Add additional section
	for _, rr := range resp.Extra {
		sb.WriteString(rr.String())
		sb.WriteString("\n")
	}

	return strings.TrimSpace(sb.String())
}

// getSystemResolver returns the system's default DNS resolver.
func getSystemResolver() string {
	// Try to read from resolv.conf on Unix systems
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err == nil && len(config.Servers) > 0 {
		return net.JoinHostPort(config.Servers[0], config.Port)
	}

	// Fallback to Google DNS
	return "8.8.8.8:53"
}

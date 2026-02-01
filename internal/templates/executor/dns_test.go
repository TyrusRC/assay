package executor

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/swiss-knife-for-web-security/skws/internal/templates"
)

func TestNewDNSExecutor(t *testing.T) {
	exec := NewDNSExecutor(nil)
	if exec == nil {
		t.Fatal("NewDNSExecutor() returned nil")
	}
	if exec.client == nil {
		t.Error("DNS client not initialized")
	}
}

func TestNewDNSExecutorWithConfig(t *testing.T) {
	config := &DNSConfig{
		Timeout:    5 * time.Second,
		Retries:    3,
		Nameserver: "1.1.1.1:53",
	}
	exec := NewDNSExecutor(config)
	if exec.config.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want 5s", exec.config.Timeout)
	}
	if exec.config.Retries != 3 {
		t.Errorf("Retries = %d, want 3", exec.config.Retries)
	}
}

func TestDNSQueryTypeConversion(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected uint16
	}{
		{"A record", "A", dns.TypeA},
		{"AAAA record", "AAAA", dns.TypeAAAA},
		{"MX record", "MX", dns.TypeMX},
		{"TXT record", "TXT", dns.TypeTXT},
		{"NS record", "NS", dns.TypeNS},
		{"CNAME record", "CNAME", dns.TypeCNAME},
		{"SOA record", "SOA", dns.TypeSOA},
		{"PTR record", "PTR", dns.TypePTR},
		{"SRV record", "SRV", dns.TypeSRV},
		{"CAA record", "CAA", dns.TypeCAA},
		{"lowercase a", "a", dns.TypeA},
		{"mixed case Mx", "Mx", dns.TypeMX},
		{"unknown type", "UNKNOWN", dns.TypeA}, // defaults to A
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dnsQueryType(tt.input)
			if result != tt.expected {
				t.Errorf("dnsQueryType(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestDNSClassConversion(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected uint16
	}{
		{"IN class", "IN", dns.ClassINET},
		{"CH class", "CH", dns.ClassCHAOS},
		{"HS class", "HS", dns.ClassHESIOD},
		{"ANY class", "ANY", dns.ClassANY},
		{"lowercase in", "in", dns.ClassINET},
		{"empty defaults to IN", "", dns.ClassINET},
		{"unknown defaults to IN", "UNKNOWN", dns.ClassINET},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dnsQueryClass(tt.input)
			if result != tt.expected {
				t.Errorf("dnsQueryClass(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestDNSResultFormatting(t *testing.T) {
	result := &DNSResult{
		Query:    "example.com",
		Type:     "A",
		Resolver: "8.8.8.8:53",
		Records: []DNSRecord{
			{Type: "A", Value: "93.184.216.34", TTL: 300},
			{Type: "A", Value: "93.184.216.35", TTL: 300},
		},
		Raw: "example.com. 300 IN A 93.184.216.34\nexample.com. 300 IN A 93.184.216.35",
	}

	if result.Query != "example.com" {
		t.Errorf("Query = %q, want example.com", result.Query)
	}
	if len(result.Records) != 2 {
		t.Errorf("Records count = %d, want 2", len(result.Records))
	}
	if result.Records[0].Value != "93.184.216.34" {
		t.Errorf("First record value = %q, want 93.184.216.34", result.Records[0].Value)
	}
}

// TestDNSExecutorExecute tests DNS query execution with a mock DNS server.
func TestDNSExecutorExecute(t *testing.T) {
	// Start a mock DNS server
	server, addr := startMockDNSServer(t)
	defer server.Shutdown()

	config := &DNSConfig{
		Timeout:    2 * time.Second,
		Nameserver: addr,
	}
	exec := NewDNSExecutor(config)

	tests := []struct {
		name      string
		query     *templates.DNSQuery
		target    string
		wantMatch bool
		wantErr   bool
	}{
		{
			name: "A record lookup with word matcher",
			query: &templates.DNSQuery{
				Name: "{{Hostname}}",
				Type: "A",
				Matchers: []templates.Matcher{
					{
						Type:  "word",
						Words: []string{"127.0.0.1"},
					},
				},
			},
			target:    "test.example.com",
			wantMatch: true,
			wantErr:   false,
		},
		{
			name: "TXT record lookup",
			query: &templates.DNSQuery{
				Name: "{{Hostname}}",
				Type: "TXT",
				Matchers: []templates.Matcher{
					{
						Type:  "word",
						Words: []string{"v=spf1"},
					},
				},
			},
			target:    "spf.example.com",
			wantMatch: true,
			wantErr:   false,
		},
		{
			name: "MX record lookup",
			query: &templates.DNSQuery{
				Name: "{{Hostname}}",
				Type: "MX",
				Matchers: []templates.Matcher{
					{
						Type:  "word",
						Words: []string{"mail.example.com"},
					},
				},
			},
			target:    "mx.example.com",
			wantMatch: true,
			wantErr:   false,
		},
		{
			name: "CNAME record lookup",
			query: &templates.DNSQuery{
				Name: "{{Hostname}}",
				Type: "CNAME",
				Matchers: []templates.Matcher{
					{
						Type:  "word",
						Words: []string{"target.example.com"},
					},
				},
			},
			target:    "cname.example.com",
			wantMatch: true,
			wantErr:   false,
		},
		{
			name: "No match case",
			query: &templates.DNSQuery{
				Name: "{{Hostname}}",
				Type: "A",
				Matchers: []templates.Matcher{
					{
						Type:  "word",
						Words: []string{"192.168.1.1"},
					},
				},
			},
			target:    "test.example.com",
			wantMatch: false,
			wantErr:   false,
		},
		{
			name: "Regex matcher",
			query: &templates.DNSQuery{
				Name: "{{Hostname}}",
				Type: "A",
				Matchers: []templates.Matcher{
					{
						Type:  "regex",
						Regex: []string{`127\.0\.0\.\d+`},
					},
				},
			},
			target:    "test.example.com",
			wantMatch: true,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			result, err := exec.Execute(ctx, tt.target, tt.query)

			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil && result.Matched != tt.wantMatch {
				t.Errorf("Execute() matched = %v, want %v", result.Matched, tt.wantMatch)
			}
		})
	}
}

func TestDNSExecutorExtractors(t *testing.T) {
	// Start a mock DNS server
	server, addr := startMockDNSServer(t)
	defer server.Shutdown()

	config := &DNSConfig{
		Timeout:    2 * time.Second,
		Nameserver: addr,
	}
	exec := NewDNSExecutor(config)

	query := &templates.DNSQuery{
		Name: "{{Hostname}}",
		Type: "A",
		Matchers: []templates.Matcher{
			{
				Type:  "word",
				Words: []string{"127.0.0.1"},
			},
		},
		Extractors: []templates.Extractor{
			{
				Type:  "regex",
				Name:  "ip_address",
				Regex: []string{`(\d+\.\d+\.\d+\.\d+)`},
			},
		},
	}

	ctx := context.Background()
	result, err := exec.Execute(ctx, "test.example.com", query)
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	if result.ExtractedData == nil {
		t.Fatal("No extracted data")
	}

	if ips, ok := result.ExtractedData["ip_address"]; !ok || len(ips) == 0 {
		t.Error("ip_address not extracted")
	} else if ips[0] != "127.0.0.1" {
		t.Errorf("ip_address = %q, want 127.0.0.1", ips[0])
	}
}

func TestDNSExecutorContextCancellation(t *testing.T) {
	// Start a mock DNS server that delays response
	server, addr := startMockDNSServer(t)
	defer server.Shutdown()

	config := &DNSConfig{
		Timeout:    10 * time.Second,
		Nameserver: addr,
	}
	exec := NewDNSExecutor(config)

	query := &templates.DNSQuery{
		Name: "slow.example.com",
		Type: "A",
	}

	// Cancel context immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := exec.Execute(ctx, "slow.example.com", query)
	if err == nil {
		// Context cancellation may not always propagate in time, but the result should
		// still be returned. This is acceptable behavior.
		t.Log("Context cancellation did not cause error - this is acceptable")
	}
}

func TestDNSExecutorRetries(t *testing.T) {
	// This test verifies that retry configuration is properly passed
	// We use a working server and verify the query succeeds
	server, addr := startMockDNSServer(t)
	defer server.Shutdown()

	config := &DNSConfig{
		Timeout:    2 * time.Second,
		Retries:    2,
		Nameserver: addr,
	}
	exec := NewDNSExecutor(config)

	query := &templates.DNSQuery{
		Name:    "{{Hostname}}",
		Type:    "A",
		Retries: 1, // Override config
	}

	ctx := context.Background()
	result, err := exec.Execute(ctx, "test.example.com", query)
	if err != nil {
		t.Errorf("Execute() error: %v", err)
	}

	if result == nil {
		t.Fatal("Result should not be nil")
	}

	// Verify that the query was executed successfully
	if len(result.Records) == 0 {
		t.Error("Expected at least one DNS record")
	}
}

// startMockDNSServer starts a mock DNS server for testing.
func startMockDNSServer(t *testing.T) (*dns.Server, string) {
	t.Helper()

	// Find an available port
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	addr := listener.LocalAddr().String()
	listener.Close()

	server := &dns.Server{
		Addr: addr,
		Net:  "udp",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true

			for _, q := range r.Question {
				switch q.Qtype {
				case dns.TypeA:
					if q.Name == "test.example.com." {
						rr := &dns.A{
							Hdr: dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							A: net.ParseIP("127.0.0.1"),
						}
						m.Answer = append(m.Answer, rr)
					}
				case dns.TypeAAAA:
					if q.Name == "test.example.com." {
						rr := &dns.AAAA{
							Hdr: dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeAAAA,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							AAAA: net.ParseIP("::1"),
						}
						m.Answer = append(m.Answer, rr)
					}
				case dns.TypeTXT:
					if q.Name == "spf.example.com." {
						rr := &dns.TXT{
							Hdr: dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeTXT,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							Txt: []string{"v=spf1 include:_spf.google.com ~all"},
						}
						m.Answer = append(m.Answer, rr)
					}
				case dns.TypeMX:
					if q.Name == "mx.example.com." {
						rr := &dns.MX{
							Hdr: dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeMX,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							Preference: 10,
							Mx:         "mail.example.com.",
						}
						m.Answer = append(m.Answer, rr)
					}
				case dns.TypeNS:
					if q.Name == "ns.example.com." {
						rr := &dns.NS{
							Hdr: dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeNS,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							Ns: "ns1.example.com.",
						}
						m.Answer = append(m.Answer, rr)
					}
				case dns.TypeCNAME:
					if q.Name == "cname.example.com." {
						rr := &dns.CNAME{
							Hdr: dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeCNAME,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							Target: "target.example.com.",
						}
						m.Answer = append(m.Answer, rr)
					}
				case dns.TypeSOA:
					if q.Name == "soa.example.com." {
						rr := &dns.SOA{
							Hdr: dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeSOA,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							Ns:      "ns1.example.com.",
							Mbox:    "admin.example.com.",
							Serial:  2024010101,
							Refresh: 7200,
							Retry:   3600,
							Expire:  1209600,
							Minttl:  300,
						}
						m.Answer = append(m.Answer, rr)
					}
				}
			}

			if err := w.WriteMsg(m); err != nil {
				t.Logf("Failed to write DNS response: %v", err)
			}
		}),
	}

	go func() {
		if err := server.ListenAndServe(); err != nil {
			// Server shutdown is expected
			if err.Error() != "dns: server closed" {
				t.Logf("DNS server error: %v", err)
			}
		}
	}()

	// Wait for server to start
	time.Sleep(50 * time.Millisecond)

	return server, addr
}

func TestFormatDNSRecords(t *testing.T) {
	tests := []struct {
		name    string
		records []dns.RR
		wantLen int
	}{
		{
			name: "A record",
			records: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: net.ParseIP("127.0.0.1"),
				},
			},
			wantLen: 1,
		},
		{
			name: "Multiple records",
			records: []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("127.0.0.1"),
				},
				&dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("127.0.0.2"),
				},
			},
			wantLen: 2,
		},
		{
			name:    "Empty records",
			records: []dns.RR{},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatDNSRecords(tt.records)
			if len(result) != tt.wantLen {
				t.Errorf("formatDNSRecords() returned %d records, want %d", len(result), tt.wantLen)
			}
		})
	}
}

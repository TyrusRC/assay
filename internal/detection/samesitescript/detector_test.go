package samesitescript

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
)

func TestDetector_Detect_FlagsMisconfiguredDomain(t *testing.T) {
	resolver := func(host string) ([]net.IP, error) {
		if strings.HasPrefix(host, "localhost.") {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		}
		return []net.IP{net.ParseIP("203.0.113.1")}, nil
	}
	d := NewWithResolver(resolver)
	res, err := d.Detect(context.Background(), "https://www.victim.com/path", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Errorf("expected Vulnerable=true")
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := res.Findings[0]
	if f.Type != "same_site_scripting" {
		t.Errorf("unexpected type %q", f.Type)
	}
	if f.Severity != core.SeverityMedium {
		t.Errorf("expected SeverityMedium, got %q", f.Severity)
	}
	if err := f.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
	if got := res.Domain; got != "victim.com" {
		t.Errorf("expected Domain=victim.com (eTLD+1), got %q", got)
	}
}

func TestDetector_Detect_NoFindingForPublicResolution(t *testing.T) {
	resolver := func(_ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("203.0.113.1")}, nil
	}
	d := NewWithResolver(resolver)
	res, err := d.Detect(context.Background(), "https://victim.com", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Error("expected Vulnerable=false")
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(res.Findings))
	}
}

func TestDetector_Detect_SkipsRawIP(t *testing.T) {
	resolver := func(_ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	d := NewWithResolver(resolver)
	res, err := d.Detect(context.Background(), "https://10.0.0.1/app", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Error("raw-IP targets should be skipped without findings")
	}
}

func TestDetector_Detect_ContextCancel(t *testing.T) {
	resolver := func(_ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	d := NewWithResolver(resolver)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := d.Detect(ctx, "https://victim.com", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	// Cancelled context should swallow all resolver calls and yield no findings.
	if res.Vulnerable {
		t.Error("cancelled context should produce no findings")
	}
}

func TestPublicSuffixPlusOne(t *testing.T) {
	cases := []struct{ in, want string }{
		{"example.com", "example.com"},
		{"www.example.com", "example.com"},
		{"a.b.c.example.com", "example.com"},
		{"example", "example"},
	}
	for _, c := range cases {
		if got := publicSuffixPlusOne(c.in); got != c.want {
			t.Errorf("publicSuffixPlusOne(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNew_UsesDefaultResolver(t *testing.T) {
	d := New()
	if d.resolver == nil {
		t.Error("New() must populate a non-nil resolver")
	}
}

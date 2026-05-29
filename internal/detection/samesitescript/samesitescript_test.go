package samesitescript

import (
	"net"
	"testing"
)

func TestProbeHosts_NonEmpty(t *testing.T) {
	got := ProbeHosts("victim.com")
	if len(got) < 3 {
		t.Errorf("expected at least 3 same-site script probe hosts, got %d", len(got))
	}
	want := []string{
		"localhost.victim.com",
		"127.0.0.1.victim.com",
	}
	seen := make(map[string]bool, len(got))
	for _, h := range got {
		seen[h] = true
	}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("missing required probe host: %q", w)
		}
	}
}

func TestProbeHosts_EmptyDomain(t *testing.T) {
	if got := ProbeHosts(""); got != nil {
		t.Errorf("expected nil for empty domain, got %v", got)
	}
}

func TestEvaluate_Vulnerable_WhenLocalhostResolvesLoopback(t *testing.T) {
	res := Evaluate("victim.com", func(host string) ([]net.IP, error) {
		switch host {
		case "localhost.victim.com":
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		case "127.0.0.1.victim.com":
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		}
		return []net.IP{net.ParseIP("203.0.113.10")}, nil
	})
	if !res.Vulnerable {
		t.Errorf("expected Vulnerable=true when subdomain points to 127.0.0.1, got %+v", res)
	}
	if len(res.MisconfiguredHosts) == 0 {
		t.Errorf("expected at least one misconfigured host listed")
	}
}

func TestEvaluate_NotVulnerable_WhenSubdomainResolvesPublic(t *testing.T) {
	res := Evaluate("victim.com", func(_ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("203.0.113.10")}, nil
	})
	if res.Vulnerable {
		t.Errorf("expected Vulnerable=false when subdomains resolve to public IPs, got %+v", res)
	}
}

func TestEvaluate_NotVulnerable_OnDNSFailure(t *testing.T) {
	res := Evaluate("victim.com", func(_ string) ([]net.IP, error) {
		return nil, errResolverGone
	})
	if res.Vulnerable {
		t.Error("expected Vulnerable=false when resolver fails (no positive evidence)")
	}
}

func TestEvaluate_EmptyDomain(t *testing.T) {
	res := Evaluate("", nil)
	if res.Vulnerable {
		t.Error("empty domain must not be flagged vulnerable")
	}
}

var errResolverGone = &dnsErr{msg: "resolver gone"}

type dnsErr struct{ msg string }

func (e *dnsErr) Error() string { return e.msg }

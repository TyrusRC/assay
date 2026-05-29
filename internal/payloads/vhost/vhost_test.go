package vhost

import (
	"strings"
	"testing"
)

func TestCommonHostnames_MinCount(t *testing.T) {
	got := CommonHostnames()
	if len(got) < 30 {
		t.Errorf("expected at least 30 common hostnames, got %d", len(got))
	}
}

func TestCommonHostnames_CoverHighValueNames(t *testing.T) {
	required := []string{
		"admin", "api", "staging", "dev", "test", "internal",
		"jenkins", "grafana", "kibana", "prometheus",
		"vpn", "mail", "ftp", "git", "wiki",
	}
	got := CommonHostnames()
	set := make(map[string]bool, len(got))
	for _, h := range got {
		set[h] = true
	}
	for _, r := range required {
		if !set[r] {
			t.Errorf("missing required hostname: %q", r)
		}
	}
}

func TestEnvironmentPrefixes(t *testing.T) {
	got := EnvironmentPrefixes()
	if len(got) < 5 {
		t.Errorf("expected at least 5 environment prefixes, got %d", len(got))
	}
	required := []string{"dev", "staging", "test", "prod", "uat"}
	set := make(map[string]bool, len(got))
	for _, e := range got {
		set[e] = true
	}
	for _, r := range required {
		if !set[r] {
			t.Errorf("missing required prefix: %q", r)
		}
	}
}

func TestGenerateVHosts_ProducesFQDNs(t *testing.T) {
	got := GenerateVHosts("example.com")
	if len(got) < 30 {
		t.Errorf("expected at least 30 generated vhosts, got %d", len(got))
	}
	for _, v := range got {
		if !strings.HasSuffix(v, ".example.com") {
			t.Errorf("generated vhost %q is not a subdomain of example.com", v)
		}
	}
}

func TestGenerateVHosts_DedupesAcrossPrefixes(t *testing.T) {
	got := GenerateVHosts("x.test")
	seen := make(map[string]bool, len(got))
	for _, v := range got {
		if seen[v] {
			t.Errorf("duplicate generated vhost: %s", v)
		}
		seen[v] = true
	}
}

func TestGenerateVHosts_EmptyDomain(t *testing.T) {
	if got := GenerateVHosts(""); got != nil {
		t.Errorf("expected nil for empty domain, got %v", got)
	}
}

func TestCommonHostnames_NoDuplicates(t *testing.T) {
	seen := make(map[string]bool)
	for _, h := range CommonHostnames() {
		if seen[h] {
			t.Errorf("duplicate hostname: %s", h)
		}
		seen[h] = true
	}
}

func TestNoUppercase(t *testing.T) {
	// DNS labels are case-insensitive but lowercase is canonical;
	// uppercase entries break dedup logic in callers.
	for _, h := range CommonHostnames() {
		if strings.ToLower(h) != h {
			t.Errorf("hostname not lowercased: %q", h)
		}
	}
}

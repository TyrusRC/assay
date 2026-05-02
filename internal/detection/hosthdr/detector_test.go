package hosthdr

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	internalhttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// TestDetector_HostReflectedInLocation verifies that a server which
// builds an absolute Location header from the Host header is flagged.
// This is the password-reset hijack pattern.
func TestDetector_HostReflectedInLocation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Use whatever Host the client sent (vulnerable behavior).
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		w.Header().Set("Location", "https://"+host+"/reset?token=abc123")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	client := internalhttp.NewClient().WithFollowRedirects(false)
	d := New(client)
	res, err := d.Detect(context.Background(), server.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable || len(res.Findings) == 0 {
		t.Fatalf("expected host-header finding, got %d findings", len(res.Findings))
	}
}

// TestDetector_NoReflection verifies a hardened server (Host header
// ignored when building URLs) produces zero findings.
func TestDetector_NoReflection(t *testing.T) {
	canonical := "canonical.example.com"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://"+canonical+"/reset?token=abc")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	client := internalhttp.NewClient().WithFollowRedirects(false)
	d := New(client)
	res, err := d.Detect(context.Background(), server.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Fatalf("expected zero findings on hardened server, got %d", len(res.Findings))
	}
}

// TestDetector_BodyEcho_NotEnough confirms that a server which merely
// echoes the Host into a debug banner (but does NOT use it for absolute
// links) is NOT flagged. This is the FP class we explicitly guard against.
func TestDetector_BodyEcho_NotEnough(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>Debug: served by %s</body></html>", host)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	d := New(client)
	res, err := d.Detect(context.Background(), server.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Fatalf("debug-banner echo must not trigger finding, got %d findings: %+v", len(res.Findings), res.Findings)
	}
}

// TestDetector_CanonicalLinkPoisoned confirms reflection in
// <link rel="canonical"> is flagged — common cache-poisoning vector.
func TestDetector_CanonicalLinkPoisoned(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><head><link rel="canonical" href="https://%s/page"></head></html>`, host)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	d := New(client)
	res, err := d.Detect(context.Background(), server.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	hit := false
	for _, f := range res.Findings {
		if strings.Contains(f.Type, "Host Header Injection") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("expected canonical-link host-header finding, got %+v", res.Findings)
	}
}

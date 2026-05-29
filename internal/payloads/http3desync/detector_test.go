package http3desync

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
)

func TestDetector_Detect_NoH3_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.H3Advertised {
		t.Errorf("expected H3Advertised=false on server without Alt-Svc")
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(res.Findings))
	}
}

func TestDetector_Detect_FlagsH3Advertisement(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
		w.Header().Set("Server", "Caddy/2.7.4")
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.H3Advertised {
		t.Fatal("expected H3Advertised=true on Alt-Svc: h3=")
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	gotTypes := map[string]bool{}
	for _, f := range res.Findings {
		gotTypes[f.Type] = true
		if err := f.Validate(); err != nil {
			t.Errorf("Validate: %v", err)
		}
	}
	if !gotTypes["h3_advertised"] {
		t.Error("missing h3_advertised informational finding")
	}
	// Caddy is in the identified upstream list.
	if !gotTypes["h3_upstream_known_vuln"] {
		t.Error("missing upstream-CVE finding for Caddy")
	}
	if !res.Vulnerable {
		t.Error("expected Vulnerable=true when upstream identified")
	}
}

func TestDetector_Detect_H3WithoutKnownUpstream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Alt-Svc", `h3-29=":443"`)
		// Server header is something exotic / not in the at-risk list.
		w.Header().Set("Server", "MyAcmeServer/1.0")
		_, _ = w.Write([]byte("hi"))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.H3Advertised {
		t.Fatal("expected H3 advertised via h3-29 token")
	}
	if res.Vulnerable {
		t.Error("unknown upstream must not be flagged Vulnerable")
	}
	if len(res.Findings) != 1 {
		t.Errorf("expected exactly 1 informational finding, got %d", len(res.Findings))
	}
	if res.Findings[0].Severity != core.SeverityInfo {
		t.Errorf("expected SeverityInfo, got %q", res.Findings[0].Severity)
	}
}

func TestIsH3Advertisement(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{`h3=":443"; ma=86400`, true},
		{`h3-29=":443"`, true},
		{`H3-32=":443"`, true}, // case-insensitive
		{`h2="alt.example:443"`, false},
		{"", false},
	}
	for _, c := range cases {
		if got := isH3Advertisement(c.in); got != c.want {
			t.Errorf("isH3Advertisement(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestIdentifyUpstream(t *testing.T) {
	cases := []struct {
		server string
		empty  bool
	}{
		{"nginx/1.25.0", false},
		{"Apache/2.4.59", false},
		{"LiteSpeed", false},
		{"cloudflare", false},
		{"envoy/1.28", false},
		{"Caddy/2.7", false},
		{"MyAcmeServer/1.0", true},
		{"", true},
	}
	for _, c := range cases {
		got := identifyUpstream(c.server)
		if c.empty && got != "" {
			t.Errorf("identifyUpstream(%q) = %q, want empty", c.server, got)
		}
		if !c.empty && got == "" {
			t.Errorf("identifyUpstream(%q) = empty, want non-empty label", c.server)
		}
	}
}

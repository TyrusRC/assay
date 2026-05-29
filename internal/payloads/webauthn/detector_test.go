package webauthn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
)

func TestDetector_Detect_FindsEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/webauthn/register/begin" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"publicKey":{"challenge":"abc","rp":{"id":"victim.com","name":"V"},"pubKeyCredParams":[{"type":"public-key","alg":-7}],"attestation":"direct"}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Found) == 0 {
		t.Fatal("expected to find /webauthn/register/begin")
	}
	if res.Vulnerable {
		t.Errorf("strict policy must not be flagged Vulnerable, got %v", res.Findings)
	}
	if len(res.Findings) != 1 {
		t.Errorf("expected 1 informational finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Type != "webauthn_endpoint_discovered" {
		t.Errorf("unexpected type %q", f.Type)
	}
	if f.Severity != core.SeverityInfo {
		t.Errorf("discovery finding should be SeverityInfo, got %q", f.Severity)
	}
	if err := f.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestDetector_Detect_FlagsPolicyFootguns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/webauthn/register/begin" {
			_, _ = w.Write([]byte(`{"publicKey":{"challenge":"x","rp":{"id":"localhost","name":"L"},"attestation":"none","authenticatorSelection":{"userVerification":"discouraged","residentKey":"discouraged"}}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected Vulnerable=true on weak-policy endpoint")
	}
	hasWeakPolicy := false
	for _, f := range res.Findings {
		if f.Type == "webauthn_weak_policy" {
			hasWeakPolicy = true
			if f.Severity != core.SeverityMedium {
				t.Errorf("weak-policy severity = %q, want medium", f.Severity)
			}
			footguns, ok := f.Metadata["footguns"].([]string)
			if !ok || len(footguns) < 3 {
				t.Errorf("expected at least 3 footguns flagged, got %v", footguns)
			}
		}
	}
	if !hasWeakPolicy {
		t.Error("expected at least one weak-policy finding")
	}
}

func TestLooksLikeWebAuthn(t *testing.T) {
	cases := []struct {
		body   string
		status int
		want   bool
	}{
		{`{"publicKey":{"challenge":"x"}}`, 200, true},
		{`{"error":"InvalidStateError"}`, 400, true},
		{`{"attestation":"direct"}`, 200, true},
		{`<html>plain</html>`, 200, false},
		{``, 405, false},
	}
	for i, c := range cases {
		if got := looksLikeWebAuthn(c.body, c.status); got != c.want {
			t.Errorf("case %d: looksLikeWebAuthn(%q, %d) = %v, want %v", i, c.body, c.status, got, c.want)
		}
	}
}

func TestPolicyFootguns(t *testing.T) {
	body := `{"attestation":"none","userVerification":"discouraged","rp":{"id":"localhost","name":"x"}}`
	got := policyFootguns(body)
	if len(got) < 3 {
		t.Errorf("expected at least 3 footguns on combined weak config, got %v", got)
	}
	wantTokens := []string{"attestation=none", "userVerification=discouraged", "localhost"}
	for _, w := range wantTokens {
		found := false
		for _, g := range got {
			if strings.Contains(g, w) {
				found = true
			}
		}
		if !found {
			t.Errorf("missing footgun mentioning %q in %v", w, got)
		}
	}
}

func TestDetector_Detect_NoEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Found) != 0 {
		t.Errorf("expected no findings on a 404-everything host, got %v", res.Found)
	}
}

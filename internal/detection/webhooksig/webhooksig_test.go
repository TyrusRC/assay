package webhooksig

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
)

func TestDetector_Detect_MissingSigAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/webhook" {
			http.NotFound(w, r)
			return
		}
		// Accept anything — even without a signature.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected Vulnerable=true on unauthenticated webhook")
	}
	found := false
	for _, f := range res.Findings {
		if f.Type == "webhooksig_missing_sig_accepted" {
			found = true
			if f.Severity != core.SeverityHigh {
				t.Errorf("missing-sig severity = %q, want high", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected webhooksig_missing_sig_accepted finding")
	}
}

func TestDetector_Detect_WrongSigAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/webhook" {
			http.NotFound(w, r)
			return
		}
		// Server only checks PRESENCE of header, not value — vulnerable.
		if r.Header.Get("Stripe-Signature") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"signature missing"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected Vulnerable=true on header-only validation")
	}
	found := false
	for _, f := range res.Findings {
		if f.Type == "webhooksig_wrong_sig_accepted" {
			found = true
		}
	}
	if !found {
		t.Error("expected webhooksig_wrong_sig_accepted finding")
	}
}

func TestDetector_Detect_HardenedReceiverNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/webhook" {
			http.NotFound(w, r)
			return
		}
		// Genuine receiver: rejects everything we throw at it.
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"signature verification failed"}`))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("hardened receiver should not be flagged, got findings=%d", len(res.Findings))
	}
}

func TestDetector_Detect_404Endpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Endpoints) != 0 {
		t.Errorf("expected no endpoints discovered, got %v", res.Endpoints)
	}
}

func TestCommonEndpoints_NonEmpty(t *testing.T) {
	if len(CommonEndpoints()) < 10 {
		t.Errorf("expected at least 10 endpoints, got %d", len(CommonEndpoints()))
	}
	got := false
	for _, ep := range CommonEndpoints() {
		if ep == "/webhook" {
			got = true
		}
	}
	if !got {
		t.Error("CommonEndpoints must include /webhook")
	}
}

func TestSignatureHeaders_NonEmpty(t *testing.T) {
	got := SignatureHeaders()
	if len(got) < 8 {
		t.Errorf("expected at least 8 signature headers, got %d", len(got))
	}
	required := []string{"Stripe-Signature", "X-Hub-Signature-256", "X-Slack-Signature"}
	for _, r := range required {
		found := false
		for _, h := range got {
			if h == r {
				found = true
			}
		}
		if !found {
			t.Errorf("missing required header: %q", r)
		}
	}
}

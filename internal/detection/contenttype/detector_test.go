package contenttype

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// jsonAndAltAccepting simulates a server that happily accepts JSON, XML,
// and form-encoded bodies on the same endpoint and returns identical
// "ok" responses regardless of parser.
func jsonAndAltAccepting() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		// Reject the junk-baseline body.
		if strings.Contains(string(raw), "@@@junk@@@") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error": "could not parse body"}`))
			return
		}
		if strings.HasPrefix(ct, "application/json") ||
			strings.HasPrefix(ct, "application/xml") ||
			strings.HasPrefix(ct, "application/x-www-form-urlencoded") ||
			strings.HasPrefix(ct, "multipart/form-data") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok": true, "id": 42}`))
			return
		}
		w.WriteHeader(http.StatusUnsupportedMediaType)
	}))
}

// jsonOnly simulates a hardened endpoint that rejects every alternative
// parser with 415.
func jsonOnly() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "application/json") {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			_, _ = w.Write([]byte(`{"error":"only application/json accepted"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
}

func TestDetect_FlagsAlternativesWhenAllAccepted(t *testing.T) {
	srv := jsonAndAltAccepting()
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/api/v1/users")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected at least one alternative-parser finding, got 0")
	}

	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.Parameter] = true
	}
	if !got["application/xml"] {
		t.Errorf("expected XML alt finding, got %v", got)
	}
	if !got["application/x-www-form-urlencoded"] {
		t.Errorf("expected form-encoded alt finding, got %v", got)
	}
}

func TestDetect_NoFindingsWhenJSONOnly(t *testing.T) {
	srv := jsonOnly()
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/api/v1/users")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on hardened JSON-only endpoint, got %d", len(res.Findings))
	}
}

func TestDetect_NilClientNoOp(t *testing.T) {
	det := &Detector{client: nil}
	res, err := det.Detect(context.Background(), "http://x.test/")
	if err != nil {
		t.Fatalf("nil-client should not error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("nil-client should produce 0 findings, got %d", len(res.Findings))
	}
}

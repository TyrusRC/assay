package ormleak

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

func TestDetect_FlagsExpansionLeak(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Baseline response — no sensitive keys, ~80 bytes.
		base := `{"id":1,"name":"alice","email":"alice@example.com"}`
		// Expanded response — adds password_hash + api_key, ~3x size.
		expanded := `{"id":1,"name":"alice","email":"alice@example.com","credentials":{"password_hash":"$2b$abc","api_key":"sk_test_abc"},"audit_log":["login","login","login","login"],"sessions":[{"id":1,"token":"t1"},{"id":2,"token":"t2"},{"id":3,"token":"t3"}]}`
		if r.URL.Query().Get("include") != "" || r.URL.Query().Get("expand") != "" || r.URL.Query().Get("fields") != "" {
			_, _ = w.Write([]byte(expanded))
			return
		}
		_, _ = w.Write([]byte(base))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/users/1")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected ORM-leak finding when expansion surfaces credentials")
	}
}

func TestDetect_NoFindingWhenExpansionIgnored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":1,"name":"alice"}`))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/users/1")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings when expansion is ignored, got %d", len(res.Findings))
	}
}

func TestDetect_NoFindingWhenExpansionGrowsButNoSensitive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("include") != "" {
			// Grew but no sensitive keys.
			_, _ = w.Write([]byte(`{"id":1,"name":"alice","preferences":{"theme":"dark","lang":"en","tz":"UTC"},"badges":["one","two","three","four","five","six"]}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":1}`))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/users/1")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings when growth is benign, got %d", len(res.Findings))
	}
}

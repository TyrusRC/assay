package longpwd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

func TestDetector_Detect_FlagsVulnerableServer(t *testing.T) {
	// Server pretends to hash the password: response time scales with
	// input length to simulate bcrypt-style burn.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		pwd := r.FormValue("password")
		// 50 microseconds per byte. 100k chars → ~5s.
		time.Sleep(time.Duration(len(pwd)) * 50 * time.Microsecond)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL+"/login", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Errorf("expected Vulnerable=true on length-proportional server, got %+v", res.Analysis)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Type != "long_password_dos" {
		t.Errorf("unexpected type %q", f.Type)
	}
	if f.Severity != core.SeverityMedium {
		t.Errorf("expected SeverityMedium, got %q", f.Severity)
	}
	if err := f.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestDetector_Detect_NotVulnerableForFixedServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Constant-time response regardless of input length.
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL+"/login", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("constant-time server should not be flagged, got %+v", res.Analysis)
	}
}

func TestDetector_Detect_RequestError(t *testing.T) {
	d := New(http.DefaultClient)
	opts := DefaultOptions()
	opts.Timeout = 100 * time.Millisecond
	_, err := d.Detect(context.Background(), "http://127.0.0.1:1/login", opts)
	if err == nil {
		t.Error("expected error on unreachable host")
	}
}

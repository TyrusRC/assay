package authbypass403

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	scanhttp "github.com/TyrusRC/assay/internal/http"
)

func newClient() *scanhttp.Client {
	return scanhttp.NewClient().WithTimeout(5 * time.Second).WithFollowRedirects(false)
}

func TestDetector_NameAndDescription(t *testing.T) {
	d := New(newClient())
	if d.Name() != "authbypass403" {
		t.Errorf("Name() = %q, want authbypass403", d.Name())
	}
	if d.Description() == "" {
		t.Error("Description() is empty")
	}
}

func TestDetector_NilClientIsNoOp(t *testing.T) {
	d := New(nil)
	res, err := d.Detect(context.Background(), "https://example.invalid/admin", DefaultOptions())
	if err != nil {
		t.Fatalf("nil client: %v", err)
	}
	if res == nil || res.Vulnerable || len(res.Findings) != 0 {
		t.Errorf("expected empty result on nil client, got %+v", res)
	}
}

// TestDetector_NotProtected_NoOp ensures the detector bails when the
// baseline response is already 2xx — there's nothing to bypass.
func TestDetector_NotProtected_NoOp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("public"))
	}))
	defer srv.Close()

	res, err := New(newClient()).Detect(context.Background(), srv.URL+"/admin", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected no-op on public URL, got techniques=%v", res.Techniques)
	}
}

// TestDetector_HeaderBypass_XOriginalURL covers servers (commonly behind
// Symfony / classic IIS / older Apache reverse proxies) that trust
// X-Original-URL or X-Rewrite-URL and route to the named path regardless
// of the literal request line.
func TestDetector_HeaderBypass_XOriginalURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.Header.Get("X-Original-URL"); v == "/admin" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("admin panel"))
			return
		}
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	res, err := New(newClient()).Detect(context.Background(), srv.URL+"/admin", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected bypass; techniques=%v", res.Techniques)
	}
	if !containsTechnique(res.Techniques, "header_x_original_url") {
		t.Errorf("expected header_x_original_url; got %v", res.Techniques)
	}
}

// TestDetector_HeaderBypass_ForwardedFor covers Spring / nginx / Kong
// configurations that derive trust from X-Forwarded-For and grant
// localhost privileges to any client that claims one.
func TestDetector_HeaderBypass_ForwardedFor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xff := r.Header.Get("X-Forwarded-For")
		if strings.Contains(xff, "127.0.0.1") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("internal endpoint"))
			return
		}
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	res, err := New(newClient()).Detect(context.Background(), srv.URL+"/admin", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected bypass; techniques=%v", res.Techniques)
	}
	if !containsTechnique(res.Techniques, "header_forwarded_for_loopback") {
		t.Errorf("expected header_forwarded_for_loopback; got %v", res.Techniques)
	}
}

// TestDetector_PathBypass_SemicolonTruncation covers Tomcat / JBoss
// path-parameter handling where /admin;foo=bar still routes to /admin
// but a naive reverse-proxy ACL on the literal /admin returns 403.
func TestDetector_PathBypass_SemicolonTruncation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a reverse proxy that only checks the *literal* path
		// before the first ';' but the upstream parses the path-param
		// off and lets the request through.
		raw := r.URL.EscapedPath()
		if strings.Contains(raw, ";") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("admin panel"))
			return
		}
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	res, err := New(newClient()).Detect(context.Background(), srv.URL+"/admin", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected bypass; techniques=%v", res.Techniques)
	}
	if !containsTechnique(res.Techniques, "path_semicolon_truncation") {
		t.Errorf("expected path_semicolon_truncation; got %v", res.Techniques)
	}
}

// TestDetector_HardenedServer_NoFindings ensures a target that returns
// 403 regardless of every probe doesn't trigger any technique.
func TestDetector_HardenedServer_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	res, err := New(newClient()).Detect(context.Background(), srv.URL+"/admin", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("hardened server flagged: techniques=%v", res.Techniques)
	}
}

// TestDetector_UnauthenticatedBaseline covers a 401 (not 403) baseline
// — same logic should apply, since both indicate access control.
func TestDetector_UnauthenticatedBaseline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom-IP-Authorization") == "127.0.0.1" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	res, err := New(newClient()).Detect(context.Background(), srv.URL+"/internal", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected bypass; techniques=%v", res.Techniques)
	}
	if !containsTechnique(res.Techniques, "header_custom_ip_authorization") {
		t.Errorf("expected header_custom_ip_authorization; got %v", res.Techniques)
	}
}

func containsTechnique(list []string, needle string) bool {
	for _, s := range list {
		if s == needle {
			return true
		}
	}
	return false
}

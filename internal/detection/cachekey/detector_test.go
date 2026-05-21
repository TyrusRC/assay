package cachekey

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	scanhttp "github.com/TyrusRC/assay/internal/http"
)

func newClient() *scanhttp.Client {
	return scanhttp.NewClient().WithTimeout(5 * time.Second)
}

func TestDetector_NameAndDescription(t *testing.T) {
	d := New(newClient())
	if d.Name() != "cachekey" {
		t.Errorf("Name() = %q, want cachekey", d.Name())
	}
	if d.Description() == "" {
		t.Error("Description() is empty")
	}
}

func TestDetector_NilClientIsNoOp(t *testing.T) {
	d := New(nil)
	res, err := d.Detect(context.Background(), "https://example.invalid/", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect with nil client returned error: %v", err)
	}
	if res == nil || res.Vulnerable || len(res.Findings) != 0 {
		t.Errorf("expected empty result on nil client, got %+v", res)
	}
}

// TestDetector_SemicolonParamCloaking covers a backend that parses
// `?id=A;id=B` as a *second* `id` parameter — the cache will key on
// `id=A` but the application sees `id=B`. Detection signal: the
// response body reflects the second value, proving cache/app
// parser divergence.
func TestDetector_SemicolonParamCloaking(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Pretend the framework splits on both & and ; (Tomcat/PHP/
		// some Python frameworks behave this way).
		raw := r.URL.RawQuery
		// Find the last id= occurrence after either & or ;
		val := lastIDValue(raw)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("you asked for id=" + val))
	}))
	defer srv.Close()

	d := New(newClient())
	res, err := d.Detect(context.Background(), srv.URL+"/?id=baseline", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected vulnerability; techniques=%v", res.Techniques)
	}
	if !containsTechnique(res.Techniques, "semicolon_param_cloaking") {
		t.Errorf("expected technique 'semicolon_param_cloaking'; got %v", res.Techniques)
	}
	for _, f := range res.Findings {
		if !contains(f.CWE, "CWE-444") {
			t.Errorf("expected CWE-444 on cache-key finding; got %v", f.CWE)
		}
	}
}

// TestDetector_DuplicateParamHPP covers the classic Parameter Pollution
// cache-key surface: `?id=A&id=B` — caches typically key on the first
// occurrence, frameworks vary on which they expose to the app.
func TestDetector_DuplicateParamHPP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// PHP/ASP behavior: last occurrence wins.
		vals := r.URL.Query()["id"]
		got := ""
		if len(vals) > 0 {
			got = vals[len(vals)-1]
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("id=" + got))
	}))
	defer srv.Close()

	d := New(newClient())
	res, err := d.Detect(context.Background(), srv.URL+"/?id=baseline", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected vulnerability; techniques=%v", res.Techniques)
	}
	if !containsTechnique(res.Techniques, "duplicate_param_pollution") {
		t.Errorf("expected technique 'duplicate_param_pollution'; got %v", res.Techniques)
	}
}

// TestDetector_HardenedServer_NoFindings ensures a server that always
// picks the first occurrence (cache-aligned default) and ignores
// semicolon-separated params doesn't trigger a finding.
func TestDetector_HardenedServer_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("id") // standard Go: first occurrence
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("id=" + val))
	}))
	defer srv.Close()

	d := New(newClient())
	res, err := d.Detect(context.Background(), srv.URL+"/?id=baseline", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("hardened server flagged: techniques=%v", res.Techniques)
	}
}

// TestDetector_NoParamInURL_NoOp ensures the probe bails when there's
// nothing to mutate.
func TestDetector_NoParamInURL_NoOp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("static"))
	}))
	defer srv.Close()

	d := New(newClient())
	res, err := d.Detect(context.Background(), srv.URL+"/", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("no-param URL flagged: techniques=%v", res.Techniques)
	}
}

// TestDetector_EncodedSlashNormalization covers a backend that
// normalizes %2F differently than the cache: GET /a/b returns one
// response, GET /a%2Fb returns another. Caches that normalize before
// keying serve the same key for both, allowing cache-key smuggling.
func TestDetector_EncodedSlashNormalization(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		// Differentiate: when the raw path contains %2F the backend
		// treats it as a single segment; otherwise it's a real /.
		if strings.Contains(r.URL.EscapedPath(), "%2F") {
			_, _ = w.Write([]byte("single-segment"))
			return
		}
		_, _ = w.Write([]byte("split-segments"))
	}))
	defer srv.Close()

	d := New(newClient())
	res, err := d.Detect(context.Background(), srv.URL+"/a/b", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected encoded-slash normalization to fire; techniques=%v", res.Techniques)
	}
	if !containsTechnique(res.Techniques, "encoded_slash_normalization") {
		t.Errorf("expected technique 'encoded_slash_normalization'; got %v", res.Techniques)
	}
}

func TestSeverityHasMedium(t *testing.T) {
	if got := severityFor("semicolon_param_cloaking"); got != core.SeverityMedium {
		t.Errorf("semicolon_param_cloaking severity = %q, want medium", got)
	}
}

// lastIDValue returns the value of the *last* `id` parameter,
// treating both `&` and `;` as separators (Tomcat/PHP-style).
func lastIDValue(raw string) string {
	parts := strings.FieldsFunc(raw, func(r rune) bool { return r == '&' || r == ';' })
	last := ""
	for _, p := range parts {
		if strings.HasPrefix(p, "id=") {
			last = p[3:]
		}
	}
	return last
}

func containsTechnique(list []string, needle string) bool {
	for _, s := range list {
		if s == needle {
			return true
		}
	}
	return false
}

func contains(list []string, needle string) bool {
	for _, s := range list {
		if s == needle {
			return true
		}
	}
	return false
}

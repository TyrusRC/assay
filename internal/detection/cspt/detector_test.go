package cspt

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	assayhttp "github.com/TyrusRC/assay/internal/http"
)

func TestDetector_FindsInlineSink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		body := `<html><head><script>
			const id = new URLSearchParams(location.search).get('id');
			fetch('/api/v1/users/' + id).then(r => r.json());
		</script></head><body>hi</body></html>`
		if _, err := w.Write([]byte(body)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()

	d := New(assayhttp.NewClient())
	res, err := d.Detect(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected a CSPT finding from inline script")
	}
	if res.Findings[0].Type != "Client-Side Path Traversal" {
		t.Errorf("unexpected type %q", res.Findings[0].Type)
	}
}

func TestDetector_FindsExternalScriptSink(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		js := "var p = location.hash.slice(1); fetch(`/api/data/${p}/info`);"
		if _, err := w.Write([]byte(js)); err != nil {
			t.Error(err)
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if _, err := w.Write([]byte(`<html><body><script src="/app.js"></script></body></html>`)); err != nil {
			t.Error(err)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d := New(assayhttp.NewClient())
	res, err := d.Detect(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected a CSPT finding from external script")
	}
}

func TestDetector_CleanPageNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		body := `<html><script>
			const id = new URLSearchParams(location.search).get('id');
			fetch('/api/users?id=' + encodeURIComponent(id));
		</script></html>`
		if _, err := w.Write([]byte(body)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()

	d := New(assayhttp.NewClient())
	res, err := d.Detect(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings (query-string taint), got %d", len(res.Findings))
	}
}

func TestDetector_NilClientSafe(t *testing.T) {
	d := New(nil)
	res, err := d.Detect(context.Background(), "https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil || len(res.Findings) != 0 {
		t.Fatal("nil client should yield empty result, no panic")
	}
}

func TestDetector_NonHTMLIgnored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"ok":true}`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()

	d := New(assayhttp.NewClient())
	res, err := d.Detect(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatal("non-HTML responses should be ignored")
	}
}

// TestResolveScriptURL ensures relative script srcs resolve against the page.
func TestResolveScriptURL(t *testing.T) {
	got := resolveScriptURL("https://x.test/a/b/index.html", "../js/app.js")
	if !strings.HasSuffix(got, "/a/js/app.js") {
		t.Errorf("unexpected resolution: %q", got)
	}
}

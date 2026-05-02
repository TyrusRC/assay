package tabnabbing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

func TestDetect_FlagsTargetBlankWithoutRel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
			<a href="https://evil.example/" target="_blank">click me</a>
			<a href="https://safe.example/" target="_blank" rel="noopener">safe link</a>
			<a href="/internal" target="_blank">internal</a>
		</body></html>`))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	hrefs := map[string]bool{}
	for _, f := range res.Findings {
		hrefs[f.Parameter] = true
	}
	if !hrefs["https://evil.example/"] {
		t.Error("expected unsafe https link to be flagged")
	}
	if hrefs["https://safe.example/"] {
		t.Error("safe link with rel=noopener should NOT be flagged")
	}
}

func TestDetect_DedupesIdenticalHrefs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
			<a href="https://x.example/" target="_blank">one</a>
			<a href="https://x.example/" target="_blank">two</a>
			<a href="https://x.example/" target="_blank">three</a>
		</body></html>`))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Errorf("expected 1 deduped finding, got %d", len(res.Findings))
	}
}

func TestDetect_NoHTMLNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"unrelated":"json"}`))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, _ := det.Detect(context.Background(), srv.URL+"/")
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on JSON, got %d", len(res.Findings))
	}
}

func TestDetect_SkipsMailtoAndTel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
			<a href="mailto:x@x.test" target="_blank">email</a>
			<a href="tel:+1234" target="_blank">phone</a>
			<a href="javascript:alert(1)" target="_blank">js</a>
			<a href="#section" target="_blank">fragment</a>
		</body></html>`))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, _ := det.Detect(context.Background(), srv.URL+"/")
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on non-http hrefs, got %d", len(res.Findings))
	}
}

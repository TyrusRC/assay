package phpinject

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
)

func TestDetector_Detect_NoParams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected Vulnerable=false on no-param URL")
	}
}

func TestDetector_Detect_FlagsPHPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/7.4")
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "/e") || strings.Contains(q, "php://input") || strings.Contains(q, "extract") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("<b>PHP Fatal error: </b>  preg_replace(): The /e modifier is no longer supported"))
			return
		}
		_, _ = w.Write([]byte("normal"))
	}))
	defer srv.Close()
	d := New(srv.Client())
	opts := DefaultOptions()
	opts.ConfirmedPHPOnly = false
	res, err := d.Detect(context.Background(), srv.URL+"/?q=baseline", opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected Vulnerable=true on PHP error reflection")
	}
	for _, f := range res.Findings {
		if !strings.HasPrefix(f.Type, "php_") {
			t.Errorf("unexpected type %q", f.Type)
		}
		if f.Parameter != "q" {
			t.Errorf("unexpected Parameter %q", f.Parameter)
		}
		if err := f.Validate(); err != nil {
			t.Errorf("Validate: %v", err)
		}
	}
	if !res.PHPDetected {
		t.Errorf("expected PHPDetected=true")
	}
}

func TestDetector_Detect_ConfirmedPHPOnlyGate(t *testing.T) {
	called := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		_, _ = w.Write([]byte("plain non-PHP page"))
	}))
	defer srv.Close()
	d := New(srv.Client())
	opts := DefaultOptions() // ConfirmedPHPOnly=true
	res, err := d.Detect(context.Background(), srv.URL+"/?q=hello", opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected Vulnerable=false on non-PHP target")
	}
}

func TestIsPHPResponse_HeaderVariants(t *testing.T) {
	cases := []struct {
		header http.Header
		body   string
		want   bool
	}{
		{http.Header{"X-Powered-By": {"PHP/8.1.0"}}, "", true},
		{http.Header{"X-Powered-By": {"Express"}}, "", false},
		{http.Header{"Set-Cookie": {"PHPSESSID=abc; Path=/"}}, "", true},
		{http.Header{}, "PHP Version 8.1.0", true},
		{http.Header{}, "<html>nothing</html>", false},
	}
	for i, c := range cases {
		resp := &http.Response{Header: c.header}
		if got := isPHPResponse(resp, c.body); got != c.want {
			t.Errorf("case %d: isPHPResponse() = %v, want %v", i, got, c.want)
		}
	}
}

func TestMapSeverity(t *testing.T) {
	cases := []struct {
		in   Sink
		want core.Severity
	}{
		{SinkAssert, core.SeverityCritical},
		{SinkPregReplace, core.SeverityCritical},
		{SinkInclude, core.SeverityCritical},
		{SinkUnsafeUnser, core.SeverityCritical},
		{SinkObjectInst, core.SeverityHigh},
		{SinkExtract, core.SeverityMedium},
	}
	for _, c := range cases {
		if got := mapSeverity(c.in); got != c.want {
			t.Errorf("mapSeverity(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRemediationFor_EachSink(t *testing.T) {
	for _, s := range []Sink{SinkExtract, SinkAssert, SinkPregReplace, SinkCallUserFunc, SinkCreateFunction, SinkInclude, SinkUnsafeUnser, SinkObjectInst} {
		if got := remediationFor(s); got == "" {
			t.Errorf("remediationFor(%q) returned empty", s)
		}
	}
}

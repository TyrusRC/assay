package arginject

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

func TestDetector_Detect_FlagsCurlError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a server that pipes user input into a curl call.
		v := r.URL.Query().Get("url")
		if strings.HasPrefix(v, "-") || strings.HasPrefix(v, "--") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("curl: option --upload-file: requires parameter\ncurl: try 'curl --help'"))
			return
		}
		_, _ = w.Write([]byte("fetched"))
	}))
	defer srv.Close()
	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL+"/?url=https://example.com", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected Vulnerable=true on curl error reflection")
	}
	found := false
	for _, f := range res.Findings {
		if !strings.HasPrefix(f.Type, "argument_injection_") {
			t.Errorf("unexpected type %q", f.Type)
		}
		if v := f.Metadata["binary"]; v == "curl" {
			found = true
		}
		if err := f.Validate(); err != nil {
			t.Errorf("Validate: %v", err)
		}
	}
	if !found {
		t.Errorf("expected at least one curl finding, got findings=%d", len(res.Findings))
	}
}

func TestDetector_Detect_NoFalsePositiveOnPlainServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("plain ok page, no binary wrappers"))
	}))
	defer srv.Close()
	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL+"/?q=value", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected Vulnerable=false, got findings=%d", len(res.Findings))
	}
}

func TestBinaryErrorPatterns_PerBinary(t *testing.T) {
	bins := []string{"curl", "git", "tar", "find", "convert", "python", "php"}
	for _, b := range bins {
		if got := binaryErrorPatterns(b); len(got) == 0 {
			t.Errorf("binaryErrorPatterns(%q) returned empty", b)
		}
	}
	if got := binaryErrorPatterns("nonexistent"); got != nil {
		t.Errorf("expected nil for unknown binary, got %v", got)
	}
}

func TestMapSeverity(t *testing.T) {
	cases := []struct {
		in   Impact
		want core.Severity
	}{
		{ImpactRCE, core.SeverityCritical},
		{ImpactSSRF, core.SeverityHigh},
		{ImpactFileRead, core.SeverityHigh},
		{ImpactFileWrite, core.SeverityHigh},
		{ImpactInfoLeak, core.SeverityMedium},
	}
	for _, c := range cases {
		if got := mapSeverity(c.in); got != c.want {
			t.Errorf("mapSeverity(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

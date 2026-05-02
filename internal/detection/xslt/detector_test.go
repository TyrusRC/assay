package xslt

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

func TestDetect_FlagsVendorDisclosure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		// Vulnerable: server actually evaluates the stylesheet and
		// emits the vendor name.
		if strings.Contains(string(raw), "system-property") {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(`SKWS_XSLT_VENDOR=Saxonica
SKWS_XSLT_VERSION=2.0`))
			return
		}
		_, _ = w.Write([]byte("<doc>baseline</doc>"))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/transform")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	hit := false
	for _, f := range res.Findings {
		if f.Parameter == "vendor-disclosure" && f.Severity == core.SeverityHigh {
			hit = true
		}
	}
	if !hit {
		t.Errorf("expected vendor-disclosure High finding, got %+v", res.Findings)
	}
}

func TestDetect_FlagsFileRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(string(raw), "document('file:///etc/passwd')") {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(`root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin`))
			return
		}
		_, _ = w.Write([]byte("<doc>baseline</doc>"))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, _ := det.Detect(context.Background(), srv.URL+"/transform")
	hit := false
	for _, f := range res.Findings {
		if f.Parameter == "file-read" && f.Severity == core.SeverityCritical {
			hit = true
		}
	}
	if !hit {
		t.Errorf("expected file-read Critical finding, got %+v", res.Findings)
	}
}

func TestDetect_NoFindingOnInertEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Always echoes baseline regardless of payload.
		_, _ = w.Write([]byte(`<doc><probe>baseline</probe></doc>`))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, _ := det.Detect(context.Background(), srv.URL+"/transform")
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on inert endpoint, got %d", len(res.Findings))
	}
}

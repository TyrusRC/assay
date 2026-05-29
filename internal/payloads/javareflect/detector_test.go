package javareflect

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

func TestDetector_Detect_FlagsJavaError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache Tomcat/9.0")
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "Class.forName") || strings.Contains(q, "ProcessBuilder") || strings.Contains(q, "jndi") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("java.lang.ClassNotFoundException: java.lang.Runtime\n\tat java.lang.reflect.InvocationTargetException"))
			return
		}
		_, _ = w.Write([]byte("normal"))
	}))
	defer srv.Close()
	d := New(srv.Client())
	opts := DefaultOptions()
	opts.ConfirmedJavaOnly = false
	res, err := d.Detect(context.Background(), srv.URL+"/?q=hello", opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected Vulnerable=true on Java exception reflection")
	}
	f := res.Findings[0]
	if !strings.HasPrefix(f.Type, "java_reflect_") {
		t.Errorf("unexpected type %q", f.Type)
	}
	if err := f.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestIsJavaResponse_HeaderTells(t *testing.T) {
	cases := []struct {
		header http.Header
		body   string
		want   bool
	}{
		{http.Header{"Server": {"Apache Tomcat/9.0.65"}}, "", true},
		{http.Header{"Server": {"nginx/1.18"}}, "", false},
		{http.Header{"X-Powered-By": {"Servlet/3.0"}}, "", true},
		{http.Header{"Set-Cookie": {"JSESSIONID=abc; Path=/"}}, "", true},
		{http.Header{}, "java.lang.RuntimeException", true},
	}
	for i, c := range cases {
		if got := isJavaResponse(&http.Response{Header: c.header}, c.body); got != c.want {
			t.Errorf("case %d: isJavaResponse() = %v, want %v", i, got, c.want)
		}
	}
}

func TestMapSeverity(t *testing.T) {
	cases := []struct {
		in   Impact
		want core.Severity
	}{
		{ImpactRCE, core.SeverityCritical},
		{ImpactSSRF, core.SeverityHigh},
		{ImpactInfoLeak, core.SeverityMedium},
		{ImpactDoS, core.SeverityMedium},
	}
	for _, c := range cases {
		if got := mapSeverity(c.in); got != c.want {
			t.Errorf("mapSeverity(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

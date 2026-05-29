package fileops

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

func TestDetector_Detect_FlagsFSError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("path")
		if strings.Contains(v, "../") || strings.Contains(v, "..\\") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("fopen(/etc/passwd): failed to open stream: Permission denied"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL+"/?path=image.jpg", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected Vulnerable=true on FS error reflection")
	}
	for _, f := range res.Findings {
		if !strings.HasPrefix(f.Type, "fileops_") {
			t.Errorf("unexpected type %q", f.Type)
		}
		if err := f.Validate(); err != nil {
			t.Errorf("Validate: %v", err)
		}
	}
}

func TestMapSeverity(t *testing.T) {
	cases := []struct {
		in   Operation
		want core.Severity
	}{
		{OperationTamper, core.SeverityCritical},
		{OperationCreate, core.SeverityHigh},
		{OperationDelete, core.SeverityHigh},
	}
	for _, c := range cases {
		if got := mapSeverity(c.in); got != c.want {
			t.Errorf("mapSeverity(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRemediationFor_EachOperation(t *testing.T) {
	for _, op := range []Operation{OperationCreate, OperationDelete, OperationTamper} {
		if got := remediationFor(op); got == "" {
			t.Errorf("remediationFor(%q) returned empty", op)
		}
	}
}

func TestEvaluationMarker_SkipsBaseline(t *testing.T) {
	body := "fopen(...) failed: Permission denied — already in baseline"
	baseline := body
	if got := evaluationMarker(body, baseline); got != "" {
		t.Errorf("marker already in baseline must not flag, got %q", got)
	}
}

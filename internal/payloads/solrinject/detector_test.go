package solrinject

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
		t.Errorf("expected Vulnerable=false on URL with no params")
	}
}

func TestDetector_Detect_FlagsSolrErrorReflection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		// Simulate Solr error when the query contains a Velocity-class probe.
		if strings.Contains(q, "v.template") || strings.Contains(q, "{!") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("HTTP ERROR 500\norg.apache.solr.common.SolrException: SolrException: Unknown query parser"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	d := New(srv.Client())
	opts := DefaultOptions()
	opts.ConfirmedSolrOnly = false // don't gate RCE payloads behind a fingerprint
	res, err := d.Detect(context.Background(), srv.URL+"/?q=hello", opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected Vulnerable=true on Solr error reflection")
	}
	f := res.Findings[0]
	if !strings.HasPrefix(f.Type, "solr_") {
		t.Errorf("expected type prefix solr_, got %q", f.Type)
	}
	if f.Parameter != "q" {
		t.Errorf("expected Parameter=q, got %q", f.Parameter)
	}
	if err := f.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
	if !res.SolrDetected {
		t.Errorf("expected SolrDetected=true after error-pattern hit")
	}
}

func TestDetector_Detect_GatesRCEUntilSolrConfirmed(t *testing.T) {
	called := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		_, _ = w.Write([]byte("plain non-solr page"))
	}))
	defer srv.Close()
	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL+"/?q=hello", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected Vulnerable=false on non-Solr server")
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
		{ImpactInfoLeak, core.SeverityMedium},
	}
	for _, c := range cases {
		if got := mapSeverity(c.in); got != c.want {
			t.Errorf("mapSeverity(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEvaluationMarker_RequiresNewSignal(t *testing.T) {
	p := Payload{Value: `{!join from=id}*:*`, Technique: "join", Impact: ImpactInfoLeak}
	body := "SolrException: Cannot parse"
	baseline := "SolrException: Cannot parse" // marker already present
	if got := evaluationMarker(p, body, baseline); got != "" {
		t.Errorf("marker already in baseline must not flag, got %q", got)
	}
	body2 := "SolrException: Cannot parse new error"
	if got := evaluationMarker(p, body2, "ok"); got == "" {
		t.Error("expected non-empty marker when body has new Solr error")
	}
}

package rscinject

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
)

func TestDetector_Detect_NoRSCFingerprint_NoOp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>plain old html</html>"))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected Vulnerable=false on non-RSC target")
	}
	if res.RSCDetected {
		t.Errorf("expected RSCDetected=false on non-RSC body")
	}
}

func TestDetector_Detect_FlagsHeaderInjection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Baseline: standard Next.js shell.
		baselineBody := `<html><body><script>self.__next_f=[];self.__next_f.push([1,""])</script></body></html>`

		// When Next-Router-State-Tree header is set, return a "different
		// segment" body — simulates server honouring the header.
		if r.Header.Get("Next-Router-State-Tree") != "" {
			_, _ = w.Write([]byte(`<html><body>ADMIN PANEL</body></html>`))
			return
		}
		// Other RSC negotiation headers — return a third variant to
		// demonstrate cache-key vector hits.
		if r.Header.Get("x-rsc") != "" {
			_, _ = w.Write([]byte(`<html><body>RSC PREFETCH</body></html>`))
			return
		}
		_, _ = w.Write([]byte(baselineBody))
	}))
	defer srv.Close()

	d := New(srv.Client())
	opts := DefaultOptions()
	res, err := d.Detect(context.Background(), srv.URL, opts)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.RSCDetected {
		t.Fatal("expected RSCDetected=true on __next_f fingerprint")
	}
	if !res.Vulnerable {
		t.Fatal("expected Vulnerable=true when server returns different body for negotiation headers")
	}
	gotVectors := map[Vector]bool{}
	for _, f := range res.Findings {
		v := f.Metadata["vector"].(string)
		gotVectors[Vector(v)] = true
		if !strings.HasPrefix(f.Type, "rsc_") {
			t.Errorf("unexpected type %q", f.Type)
		}
		if err := f.Validate(); err != nil {
			t.Errorf("Validate: %v", err)
		}
	}
	// We should have hit at least the header-injection vector.
	if !gotVectors[VectorHeaderInjection] && !gotVectors[VectorCacheKey] {
		t.Errorf("expected at least one HeaderInjection or CacheKey finding, got %v", gotVectors)
	}
}

func TestDetector_Detect_FlagsFlightParserError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Standard Next.js fingerprinted baseline.
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<script>self.__next_f.push([])</script>`))
			return
		}
		// Server-Action POST: leak a Next.js parser error.
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`Server Action not found`))
	}))
	defer srv.Close()

	d := New(srv.Client())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.RSCDetected {
		t.Fatal("expected RSCDetected=true")
	}
	if !res.Vulnerable {
		t.Fatal("expected at least one finding on parser-error leak")
	}
	found := false
	for _, f := range res.Findings {
		if strings.Contains(f.Evidence, "flight-parser") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a flight-parser evidence string in findings")
	}
}

func TestMapSeverity(t *testing.T) {
	cases := []struct {
		in   Impact
		want core.Severity
	}{
		{ImpactRCE, core.SeverityCritical},
		{ImpactPrivilegeEscalation, core.SeverityHigh},
		{ImpactAuthBypass, core.SeverityHigh},
		{ImpactComponentLeak, core.SeverityMedium},
	}
	for _, c := range cases {
		if got := mapSeverity(c.in); got != c.want {
			t.Errorf("mapSeverity(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestHasFingerprint(t *testing.T) {
	if !hasFingerprint(`<script>self.__next_f.push([])</script>`) {
		t.Error("expected hit on self.__next_f")
	}
	if hasFingerprint(`<html>plain</html>`) {
		t.Error("plain body must not fingerprint as Next.js")
	}
}

func TestRemediationFor_EachVector(t *testing.T) {
	for _, v := range []Vector{VectorActionIDConfusion, VectorPayloadShape, VectorHeaderInjection, VectorCacheKey, VectorComponentLeak, VectorActionReplay} {
		if got := remediationFor(v); got == "" {
			t.Errorf("remediationFor(%q) returned empty", v)
		}
	}
}

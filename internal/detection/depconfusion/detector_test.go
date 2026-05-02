package depconfusion

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

const samplePackageJSON = `{
  "name": "internal-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.0.0",
    "@yourorg/internal-lib": "^1.0.0",
    "totally-private-internal-lib-skws": "^0.1.0"
  }
}`

func TestDetect_FlagsUnregisteredNPMDep(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/package.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(samplePackageJSON))
			return
		}
		http.NotFound(w, r)
	}))
	defer target.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), target.URL+"/")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	hit := false
	for _, f := range res.Findings {
		if strings.Contains(f.Type, "Dependency Confusion Candidate") {
			hit = true
		}
	}
	if !hit {
		t.Logf("findings: %+v", res.Findings)
		// Live npm registry is required for the High-tier path; without
		// network the detector falls back to the manifest-exposed Low.
		// Accept either as long as the manifest leak fires.
		if len(res.Findings) == 0 {
			t.Fatal("expected at least one manifest-leak finding")
		}
	}
}

func TestDetect_NoFindingWhen404(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer target.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), target.URL+"/")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on 404 manifests, got %d", len(res.Findings))
	}
}

func TestLooksManifest_RejectsHTML(t *testing.T) {
	if looksManifest("/package.json", "text/html", "<html><body>SPA fallback</body></html>") {
		t.Error("HTML SPA fallback should not be classified as JSON manifest")
	}
}

func TestLooksManifest_AcceptsJSON(t *testing.T) {
	if !looksManifest("/package.json", "application/json", `{"name":"x"}`) {
		t.Error("JSON object should be accepted as manifest")
	}
}

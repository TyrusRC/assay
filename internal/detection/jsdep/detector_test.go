package jsdep

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

func TestIdentifyLibrary_AngularDashedFilename(t *testing.T) {
	lib := IdentifyLibrary("https://example.test/resources/js/angular_1-7-7.js")
	if lib == nil {
		t.Fatal("expected angular library identified, got nil")
	}
	if lib.Name != "AngularJS" {
		t.Errorf("Name = %q, want %q", lib.Name, "AngularJS")
	}
	if lib.Version != "1.7.7" {
		t.Errorf("Version = %q, want %q (filename used '_'/'-' separators)", lib.Version, "1.7.7")
	}
	if lib.CPEProduct != "angular.js" || lib.CPEVendor != "angularjs" {
		t.Errorf("CPE = %s:%s, want angularjs:angular.js", lib.CPEVendor, lib.CPEProduct)
	}
}

func TestIdentifyLibrary_JQueryStandard(t *testing.T) {
	lib := IdentifyLibrary("https://cdn.example.test/jquery-3.4.1.min.js")
	if lib == nil {
		t.Fatal("expected jquery library identified, got nil")
	}
	if lib.Version != "3.4.1" {
		t.Errorf("Version = %q, want 3.4.1", lib.Version)
	}
}

func TestIdentifyLibrary_UnknownReturnsNil(t *testing.T) {
	if got := IdentifyLibrary("https://example.test/static/app-bundle.js"); got != nil {
		t.Errorf("expected nil for unknown library, got %+v", got)
	}
	if got := IdentifyLibrary(""); got != nil {
		t.Errorf("expected nil for empty url, got %+v", got)
	}
}

func TestCPEName_Format(t *testing.T) {
	got := CPEName("angularjs", "angular.js", "1.7.7")
	want := "cpe:2.3:a:angularjs:angular.js:1.7.7:*:*:*:*:*:*:*"
	if got != want {
		t.Errorf("CPEName mismatch:\n got: %s\nwant: %s", got, want)
	}
	if CPEName("", "x", "1") != "" {
		t.Error("expected empty CPE on missing vendor")
	}
}

// nvdResponseFixture returns one CVE shaped exactly like an NVD v2 reply.
// Used to confirm the JSON projection picks up id, severity, score, and
// English description.
func nvdResponseFixture(cveID, severity string, score float64) string {
	return fmt.Sprintf(`{
		"resultsPerPage": 1,
		"startIndex": 0,
		"totalResults": 1,
		"vulnerabilities": [
			{
				"cve": {
					"id": %q,
					"descriptions": [
						{"lang": "en", "value": "Sample CVE for jsdep test."}
					],
					"metrics": {
						"cvssMetricV31": [
							{
								"cvssData": {
									"baseScore": %.1f,
									"baseSeverity": %q
								}
							}
						]
					}
				}
			}
		]
	}`, cveID, score, severity)
}

func TestDetector_Detect_AngularJSWithCVE(t *testing.T) {
	// NVD fake returns one CVE for any CPE query.
	nvdServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "cpeName=") {
			http.Error(w, "missing cpeName", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(nvdResponseFixture("CVE-2020-7676", "MEDIUM", 6.1)))
	}))
	defer nvdServer.Close()

	// Target serves a page that loads angular_1-7-7.js (PortSwigger lab shape).
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head>
<script src="/resources/js/angular_1-7-7.js"></script>
<script src="/resources/js/site.js"></script>
</head><body></body></html>`))
	}))
	defer targetServer.Close()

	client := skwshttp.NewClient()
	det := New(client, "")
	det.WithNVD(&NVDClient{
		Endpoint:    nvdServer.URL,
		HTTPClient:  nvdServer.Client(),
		MinInterval: 0,
	})

	res, err := det.Detect(context.Background(), targetServer.URL+"/blog")
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if len(res.Libraries) != 1 {
		t.Fatalf("expected 1 library identified, got %d (%+v)", len(res.Libraries), res.Libraries)
	}
	if res.Libraries[0].Name != "AngularJS" {
		t.Errorf("library name = %q, want AngularJS", res.Libraries[0].Name)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 CVE finding, got %d", len(res.Findings))
	}
	if res.Findings[0].CVSS != 6.1 {
		t.Errorf("finding CVSS = %v, want 6.1", res.Findings[0].CVSS)
	}
	if !strings.Contains(res.Findings[0].Description, "CVE-2020-7676") {
		t.Errorf("finding description missing CVE id: %q", res.Findings[0].Description)
	}
}

func TestDetector_Detect_NoLibrariesNoFindings(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><script src="/static/app.js"></script></head></html>`))
	}))
	defer targetServer.Close()

	// NVD must NOT be hit when no libraries are identified.
	called := 0
	nvdServer := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called++
	}))
	defer nvdServer.Close()

	det := New(skwshttp.NewClient(), "")
	det.WithNVD(&NVDClient{Endpoint: nvdServer.URL, HTTPClient: nvdServer.Client(), MinInterval: 0})

	res, err := det.Detect(context.Background(), targetServer.URL)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(res.Findings))
	}
	if called != 0 {
		t.Errorf("expected 0 NVD calls when no libraries detected, got %d", called)
	}
}

func TestDetector_Detect_NVDFailureReturnsLibrariesQuietly(t *testing.T) {
	// NVD returns 503 — detector should not error, but should still
	// surface the library inventory so the caller sees what was loaded.
	nvdServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer nvdServer.Close()

	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><script src="/jquery-3.4.1.min.js"></script></head></html>`))
	}))
	defer targetServer.Close()

	det := New(skwshttp.NewClient(), "")
	det.WithNVD(&NVDClient{Endpoint: nvdServer.URL, HTTPClient: nvdServer.Client(), MinInterval: 0})

	res, err := det.Detect(context.Background(), targetServer.URL)
	if err != nil {
		t.Fatalf("Detect should swallow NVD outage; got error %v", err)
	}
	if len(res.Libraries) != 1 {
		t.Errorf("expected library inventory even on NVD outage, got %d", len(res.Libraries))
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on NVD outage, got %d", len(res.Findings))
	}
}

// TestExtractScriptSrcs_AbsoluteAndRelative confirms relative srcs are
// resolved against the base URL and absolute srcs are passed through.
// This matters because IdentifyLibrary inspects the filename, and a
// missing scheme breaks url.Parse downstream.
func TestExtractScriptSrcs_AbsoluteAndRelative(t *testing.T) {
	body := `<html><head>
<script src="/resources/js/angular_1-7-7.js"></script>
<script src='https://cdn.example.com/jquery-3.4.1.min.js'></script>
</head></html>`
	base, _ := url.Parse("https://target.test/blog")
	got := extractScriptSrcs(body, base)
	if len(got) != 2 {
		t.Fatalf("expected 2 src URLs, got %d (%v)", len(got), got)
	}
	if !strings.HasPrefix(got[0], "https://target.test/") {
		t.Errorf("relative src not resolved: %q", got[0])
	}
	if got[1] != "https://cdn.example.com/jquery-3.4.1.min.js" {
		t.Errorf("absolute src altered: %q", got[1])
	}
}

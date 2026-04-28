package subtakeover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	internalhttp "github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/payloads/subtakeover"
)

func TestNew(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	if detector == nil {
		t.Fatal("New() returned nil")
	}
}

func TestDetector_WithVerbose(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client).WithVerbose(true)

	if !detector.verbose {
		t.Error("WithVerbose() did not set verbose flag")
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.Timeout <= 0 {
		t.Error("Timeout should be positive")
	}
}

func TestDetector_DetectGitHubPagesTakeover(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("There isn't a GitHub Pages site here."))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	service := subtakeover.Service{
		Name:        "GitHub Pages",
		CNames:      []string{".github.io"},
		Fingerprint: []string{"There isn't a GitHub Pages site here."},
		HTTPCheck:   true,
		Severity:    "high",
	}

	result := detector.checkHTTPFingerprint(
		context.Background(),
		server.URL,
		"test.github.io",
		service,
	)

	if result == nil {
		t.Fatal("Expected finding for GitHub Pages takeover")
	}

	if result.Type != "Subdomain Takeover" {
		t.Errorf("Expected type 'Subdomain Takeover', got %s", result.Type)
	}
}

func TestDetector_DetectHerokuTakeover(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("No such app"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	service := subtakeover.Service{
		Name:        "Heroku",
		CNames:      []string{".herokuapp.com"},
		Fingerprint: []string{"No such app"},
		HTTPCheck:   true,
		Severity:    "high",
	}

	result := detector.checkHTTPFingerprint(
		context.Background(),
		server.URL,
		"app.herokuapp.com",
		service,
	)

	if result == nil {
		t.Fatal("Expected finding for Heroku takeover")
	}
}

func TestDetector_DetectS3TakeoverFingerprint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	service := subtakeover.Service{
		Name:        "AWS S3",
		CNames:      []string{".s3.amazonaws.com"},
		Fingerprint: []string{"NoSuchBucket", "The specified bucket does not exist"},
		HTTPCheck:   true,
		Severity:    "high",
	}

	result := detector.checkHTTPFingerprint(
		context.Background(),
		server.URL,
		"bucket.s3.amazonaws.com",
		service,
	)

	if result == nil {
		t.Fatal("Expected finding for S3 bucket takeover")
	}
}

func TestDetector_SafeSubdomain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Welcome to our site"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	service := subtakeover.Service{
		Name:        "GitHub Pages",
		Fingerprint: []string{"There isn't a GitHub Pages site here."},
		HTTPCheck:   true,
	}

	result := detector.checkHTTPFingerprint(
		context.Background(),
		server.URL,
		"test.github.io",
		service,
	)

	if result != nil {
		t.Error("Expected no takeover finding for active site")
	}
}

func TestDetector_FingerprintMatching(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		fingerprints []string
		expected     bool
	}{
		{name: "GitHub Pages match", body: "There isn't a GitHub Pages site here.", fingerprints: []string{"There isn't a GitHub Pages site here."}, expected: true},
		{name: "Heroku match", body: "<html>No such app</html>", fingerprints: []string{"No such app"}, expected: true},
		{name: "S3 match", body: "<Error>NoSuchBucket</Error>", fingerprints: []string{"NoSuchBucket"}, expected: true},
		{name: "No match", body: "Welcome to our application", fingerprints: []string{"No such app", "NoSuchBucket"}, expected: false},
		{name: "Empty fingerprints", body: "anything", fingerprints: []string{}, expected: false},
	}

	client := internalhttp.NewClient()
	detector := New(client)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.matchesFingerprint(tt.body, tt.fingerprints)
			if result != tt.expected {
				t.Errorf("matchesFingerprint() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDetector_ServiceLookup(t *testing.T) {
	tests := []struct {
		name     string
		cname    string
		expected string
	}{
		{name: "GitHub Pages", cname: "user.github.io", expected: "GitHub Pages"},
		{name: "Heroku", cname: "app.herokuapp.com", expected: "Heroku"},
		{name: "S3", cname: "bucket.s3.amazonaws.com", expected: "AWS S3"},
		{name: "Unknown", cname: "example.com", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := subtakeover.GetServiceByCNAME(tt.cname)
			if tt.expected == "" {
				if svc != nil {
					t.Errorf("Expected nil service, got %s", svc.Name)
				}
			} else {
				if svc == nil {
					t.Fatalf("Expected service %s, got nil", tt.expected)
				}
				if svc.Name != tt.expected {
					t.Errorf("Expected service %s, got %s", tt.expected, svc.Name)
				}
			}
		})
	}
}

func TestDetector_ContextCancellation(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := detector.Detect(ctx, []SubdomainInfo{
		{Subdomain: "test.example.com", CNAME: "test.github.io"},
	}, DefaultOptions())

	if err == nil {
		t.Error("Expected context cancellation error")
	}
}

func TestDetector_FindingOWASP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("There isn't a GitHub Pages site here."))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	service := subtakeover.Service{
		Name:        "GitHub Pages",
		Fingerprint: []string{"There isn't a GitHub Pages site here."},
		HTTPCheck:   true,
		Severity:    "high",
	}

	finding := detector.checkHTTPFingerprint(
		context.Background(),
		server.URL,
		"test.github.io",
		service,
	)

	if finding == nil {
		t.Fatal("Expected finding")
	}

	if len(finding.WSTG) == 0 {
		t.Error("Expected WSTG mapping")
	}
	if len(finding.CWE) == 0 {
		t.Error("Expected CWE mapping")
	}
}

func TestDetector_Detect_VulnerableSubdomain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("There isn't a GitHub Pages site here."))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	subdomains := []SubdomainInfo{
		{
			Subdomain: "vuln.example.com",
			CNAME:     "vuln.github.io",
			URL:       server.URL,
		},
	}

	result, err := detector.Detect(context.Background(), subdomains, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected result to be vulnerable")
	}
	if result.CheckedSubdomains != 1 {
		t.Errorf("CheckedSubdomains = %d, want 1", result.CheckedSubdomains)
	}
	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}
	if result.VulnerableServices["GitHub Pages"] != 1 {
		t.Errorf("VulnerableServices[GitHub Pages] = %d, want 1", result.VulnerableServices["GitHub Pages"])
	}
}

func TestDetector_Detect_MultipleSubdomains(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("There isn't a GitHub Pages site here."))
	}))
	defer server.Close()

	safeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Welcome to our site"))
	}))
	defer safeServer.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	subdomains := []SubdomainInfo{
		{Subdomain: "vuln.example.com", CNAME: "vuln.github.io", URL: server.URL},
		{Subdomain: "safe.example.com", CNAME: "safe.github.io", URL: safeServer.URL},
	}

	result, err := detector.Detect(context.Background(), subdomains, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if result.CheckedSubdomains != 2 {
		t.Errorf("CheckedSubdomains = %d, want 2", result.CheckedSubdomains)
	}
	if len(result.Findings) != 1 {
		t.Errorf("len(Findings) = %d, want 1", len(result.Findings))
	}
}

func TestDetector_Detect_NoMatchingCNAME(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	subdomains := []SubdomainInfo{
		{Subdomain: "test.example.com", CNAME: "test.unknownservice.com"},
	}

	result, err := detector.Detect(context.Background(), subdomains, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if result.Vulnerable {
		t.Error("Should not be vulnerable with unknown CNAME")
	}
	if result.CheckedSubdomains != 1 {
		t.Errorf("CheckedSubdomains = %d, want 1", result.CheckedSubdomains)
	}
	if len(result.Findings) != 0 {
		t.Errorf("len(Findings) = %d, want 0", len(result.Findings))
	}
}

func TestDetector_Detect_EmptySubdomains(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), []SubdomainInfo{}, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if result.Vulnerable {
		t.Error("Should not be vulnerable with empty subdomains")
	}
	if result.CheckedSubdomains != 0 {
		t.Errorf("CheckedSubdomains = %d, want 0", result.CheckedSubdomains)
	}
}

func TestDetector_Detect_NonHTTPCheckService(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	// Use a service with HTTPCheck=false (like Elastic Beanstalk which uses NXDomain)
	subdomains := []SubdomainInfo{
		{Subdomain: "app.example.com", CNAME: "app.elasticbeanstalk.com"},
	}

	result, err := detector.Detect(context.Background(), subdomains, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	// Should not try HTTP check for NXDomain-only services
	if result.Vulnerable {
		t.Error("Should not detect vulnerability without HTTP check")
	}
}

func TestDetector_Detect_WithDefaultURL(t *testing.T) {
	// Test that when URL is empty, the detector builds it from the subdomain
	// We cannot actually connect, but we can verify no panic occurs
	client := internalhttp.NewClient().WithTimeout(100 * time.Millisecond)
	detector := New(client)

	subdomains := []SubdomainInfo{
		{Subdomain: "vuln.github.io", CNAME: "vuln.github.io", URL: ""},
	}

	result, err := detector.Detect(context.Background(), subdomains, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	// Connection will fail but should not panic
	if result.CheckedSubdomains != 1 {
		t.Errorf("CheckedSubdomains = %d, want 1", result.CheckedSubdomains)
	}
}

func TestDetector_FindMatchingService(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	services := subtakeover.GetServices()

	tests := []struct {
		name     string
		cname    string
		expected string
	}{
		{name: "GitHub Pages", cname: "user.github.io", expected: "GitHub Pages"},
		{name: "Heroku", cname: "app.herokuapp.com", expected: "Heroku"},
		{name: "Heroku SSL", cname: "app.herokussl.com", expected: "Heroku"},
		{name: "S3", cname: "bucket.s3.amazonaws.com", expected: "AWS S3"},
		{name: "Azure", cname: "app.azurewebsites.net", expected: "Azure"},
		{name: "Shopify", cname: "shop.myshopify.com", expected: "Shopify"},
		{name: "Fastly", cname: "cdn.fastly.net", expected: "Fastly"},
		{name: "Netlify", cname: "site.netlify.app", expected: "Netlify"},
		{name: "No match", cname: "test.example.com", expected: ""},
		{name: "Empty CNAME", cname: "", expected: ""},
		{name: "Case insensitive", cname: "APP.GITHUB.IO", expected: "GitHub Pages"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := detector.findMatchingService(tt.cname, services)
			if tt.expected == "" {
				if svc != nil {
					t.Errorf("Expected nil, got %s", svc.Name)
				}
			} else {
				if svc == nil {
					t.Fatalf("Expected %s, got nil", tt.expected)
				}
				if svc.Name != tt.expected {
					t.Errorf("Name = %q, want %q", svc.Name, tt.expected)
				}
			}
		})
	}
}

func TestDetector_MatchesFingerprint_NilFingerprints(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	result := detector.matchesFingerprint("some body", nil)
	if result {
		t.Error("matchesFingerprint() should return false for nil fingerprints")
	}
}

func TestDetector_CheckHTTPFingerprint_ConnectionError(t *testing.T) {
	// Use an invalid server URL to trigger an error
	client := internalhttp.NewClient().WithTimeout(100 * time.Millisecond)
	detector := New(client)

	service := subtakeover.Service{
		Name:        "GitHub Pages",
		Fingerprint: []string{"There isn't a GitHub Pages site here."},
		HTTPCheck:   true,
		Severity:    "high",
	}

	result := detector.checkHTTPFingerprint(
		context.Background(),
		"http://127.0.0.1:1", // Port that should not be listening
		"test.github.io",
		service,
	)

	if result != nil {
		t.Error("Expected nil finding when connection fails")
	}
}

func TestDetector_MapSeverity(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "critical", input: "critical", expected: "critical"},
		{name: "high", input: "high", expected: "high"},
		{name: "medium", input: "medium", expected: "medium"},
		{name: "low", input: "low", expected: "low"},
		{name: "CRITICAL uppercase", input: "CRITICAL", expected: "critical"},
		{name: "High mixed case", input: "High", expected: "high"},
		{name: "unknown", input: "unknown", expected: "medium"},
		{name: "empty", input: "", expected: "medium"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.mapSeverity(tt.input)
			if string(result) != tt.expected {
				t.Errorf("mapSeverity(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestDetector_CreateFinding_Fields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("No such app"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	service := subtakeover.Service{
		Name:        "Heroku",
		CNames:      []string{".herokuapp.com"},
		Fingerprint: []string{"No such app"},
		HTTPCheck:   true,
		Severity:    "high",
	}

	finding := detector.checkHTTPFingerprint(
		context.Background(),
		server.URL,
		"app.herokuapp.com",
		service,
	)

	if finding == nil {
		t.Fatal("Expected finding")
	}

	if finding.Type != "Subdomain Takeover" {
		t.Errorf("Type = %q, want %q", finding.Type, "Subdomain Takeover")
	}
	if finding.URL != server.URL {
		t.Errorf("URL = %q, want %q", finding.URL, server.URL)
	}
	if finding.Tool != "subtakeover-detector" {
		t.Errorf("Tool = %q, want %q", finding.Tool, "subtakeover-detector")
	}
	if finding.Remediation == "" {
		t.Error("Remediation should not be empty")
	}
	if finding.Description == "" {
		t.Error("Description should not be empty")
	}
	if finding.Evidence == "" {
		t.Error("Evidence should not be empty")
	}
}

func TestDetector_CreateFinding_LongBody(t *testing.T) {
	// Create a response body longer than 500 characters to test truncation
	longBody := ""
	for i := 0; i < 600; i++ {
		longBody += "A"
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("No such app" + longBody))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	service := subtakeover.Service{
		Name:        "Heroku",
		CNames:      []string{".herokuapp.com"},
		Fingerprint: []string{"No such app"},
		HTTPCheck:   true,
		Severity:    "high",
	}

	finding := detector.checkHTTPFingerprint(
		context.Background(),
		server.URL,
		"app.herokuapp.com",
		service,
	)

	if finding == nil {
		t.Fatal("Expected finding")
	}

	// Evidence should contain the truncated body with "..."
	if len(finding.Evidence) == 0 {
		t.Error("Evidence should not be empty")
	}
}

func TestDetectionResult_Fields(t *testing.T) {
	result := &DetectionResult{
		Vulnerable:         true,
		Findings:           make([]*core.Finding, 0),
		CheckedSubdomains:  5,
		VulnerableServices: map[string]int{"GitHub Pages": 2, "Heroku": 1},
	}

	if !result.Vulnerable {
		t.Error("Vulnerable should be true")
	}
	if result.CheckedSubdomains != 5 {
		t.Errorf("CheckedSubdomains = %d, want 5", result.CheckedSubdomains)
	}
	if result.VulnerableServices["GitHub Pages"] != 2 {
		t.Errorf("VulnerableServices[GitHub Pages] = %d, want 2", result.VulnerableServices["GitHub Pages"])
	}
}

func TestSubdomainInfo_Fields(t *testing.T) {
	info := SubdomainInfo{
		Subdomain: "test.example.com",
		CNAME:     "test.github.io",
		URL:       "https://test.example.com",
	}

	if info.Subdomain != "test.example.com" {
		t.Errorf("Subdomain = %q", info.Subdomain)
	}
	if info.CNAME != "test.github.io" {
		t.Errorf("CNAME = %q", info.CNAME)
	}
	if info.URL != "https://test.example.com" {
		t.Errorf("URL = %q", info.URL)
	}
}

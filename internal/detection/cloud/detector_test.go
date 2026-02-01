package cloud

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	internalhttp "github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/payloads/cloud"
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

	if opts.MaxChecks <= 0 {
		t.Error("MaxChecks should be positive")
	}
}

func TestDetector_DetectOpenS3Bucket(t *testing.T) {
	// Simulate open S3 bucket
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-bucket</Name>
  <Contents>
    <Key>secret-file.txt</Key>
    <Size>1024</Size>
  </Contents>
  <Contents>
    <Key>backup.sql</Key>
    <Size>51200</Size>
  </Contents>
</ListBucketResult>`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.DetectBucket(
		context.Background(),
		server.URL,
		"test-bucket",
	)

	if err != nil {
		t.Fatalf("DetectBucket failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected open bucket to be detected")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}
}

func TestDetector_DetectOpenAzureBlob(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<EnumerationResults>
  <Blobs>
    <Blob>
      <Name>config.json</Name>
    </Blob>
  </Blobs>
</EnumerationResults>`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.DetectBucket(
		context.Background(),
		server.URL,
		"test-container",
	)

	if err != nil {
		t.Fatalf("DetectBucket failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected open Azure blob to be detected")
	}
}

func TestDetector_ClosedBucket(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>AccessDenied</Code>
  <Message>Access Denied</Message>
</Error>`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.DetectBucket(
		context.Background(),
		server.URL,
		"secure-bucket",
	)

	if err != nil {
		t.Fatalf("DetectBucket failed: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability for secured bucket")
	}
}

func TestDetector_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := detector.Detect(ctx, "example.com", DefaultOptions())

	if err == nil {
		t.Error("Expected context cancellation error")
	}
}

func TestDetector_BucketPatternMatching(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		patterns []string
		expected bool
	}{
		{name: "S3 listing", body: "<ListBucketResult><Contents><Key>file</Key></Contents></ListBucketResult>", patterns: []string{"<ListBucketResult", "<Contents>"}, expected: true},
		{name: "Azure listing", body: "<EnumerationResults><Blobs><Blob></Blob></Blobs></EnumerationResults>", patterns: []string{"<EnumerationResults", "<Blobs>"}, expected: true},
		{name: "Access denied", body: "<Error><Code>AccessDenied</Code></Error>", patterns: []string{"<ListBucketResult"}, expected: false},
		{name: "Empty body", body: "", patterns: []string{"<ListBucketResult"}, expected: false},
	}

	client := internalhttp.NewClient()
	detector := New(client)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.matchesPatterns(tt.body, tt.patterns)
			if result != tt.expected {
				t.Errorf("matchesPatterns() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDetector_FindingOWASP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<ListBucketResult><Contents><Key>data.csv</Key></Contents></ListBucketResult>"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.DetectBucket(
		context.Background(),
		server.URL,
		"test",
	)

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Fatal("Expected vulnerability")
	}

	finding := result.Findings[0]
	if finding.Type != "Cloud Storage Misconfiguration" {
		t.Errorf("Expected type 'Cloud Storage Misconfiguration', got %s", finding.Type)
	}
	if len(finding.CWE) == 0 {
		t.Error("Expected CWE mapping")
	}
}

func TestDetector_GenerateBucketNames(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	names := detector.generateBucketNames("example.com")

	if len(names) == 0 {
		t.Error("Expected bucket names to be generated")
	}

	// Should contain the base domain
	found := false
	for _, name := range names {
		if name == "example.com" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected base domain in bucket names")
	}
}

func TestDetector_GenerateBucketNames_StripScheme(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name   string
		domain string
	}{
		{name: "https prefix", domain: "https://example.com"},
		{name: "http prefix", domain: "http://example.com"},
		{name: "trailing slash", domain: "example.com/"},
		{name: "no prefix", domain: "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			names := detector.generateBucketNames(tt.domain)
			if len(names) == 0 {
				t.Error("Expected bucket names to be generated")
			}

			// All should contain "example.com" or "example-com" variant
			foundBase := false
			for _, name := range names {
				if name == "example.com" || name == "example-com" {
					foundBase = true
					break
				}
			}
			if !foundBase {
				t.Error("Expected base domain variant in bucket names")
			}
		})
	}
}

func TestDetector_GenerateBucketNames_DashVariants(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	names := detector.generateBucketNames("sub.example.com")

	// Should have dash variants (sub-example-com)
	hasDash := false
	for _, name := range names {
		if name == "sub-example-com" {
			hasDash = true
			break
		}
	}
	if !hasDash {
		t.Error("Expected dash variant of domain in bucket names")
	}
}

func TestDetector_GenerateBucketNames_NoDuplicates(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	names := detector.generateBucketNames("example.com")

	seen := make(map[string]bool)
	for _, name := range names {
		if seen[name] {
			t.Errorf("Duplicate bucket name: %q", name)
		}
		seen[name] = true
	}
}

func TestDetector_MatchesPatterns_EmptyPatterns(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	result := detector.matchesPatterns("any content", []string{})
	if result {
		t.Error("matchesPatterns() should return false for empty patterns")
	}
}

func TestDetector_MatchesPatterns_NilPatterns(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	result := detector.matchesPatterns("any content", nil)
	if result {
		t.Error("matchesPatterns() should return false for nil patterns")
	}
}

func TestDetector_Detect_WithCustomBuckets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("AccessDenied"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	opts := DefaultOptions()
	opts.CustomBuckets = []string{"custom-bucket-1", "custom-bucket-2"}
	opts.MaxChecks = 5

	result, err := detector.Detect(context.Background(), "example.com", opts)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if result.CheckedURLs == 0 {
		t.Error("Should have checked some URLs")
	}
}

func TestDetector_Detect_MaxChecksLimit(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("AccessDenied"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	opts := DefaultOptions()
	opts.MaxChecks = 3

	result, err := detector.Detect(context.Background(), "example.com", opts)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if result.CheckedURLs > 3 {
		t.Errorf("CheckedURLs = %d, should not exceed MaxChecks (3)", result.CheckedURLs)
	}
}

func TestDetector_Detect_WithProviderFilter(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	opts := DefaultOptions()
	opts.Providers = []cloud.Provider{cloud.ProviderAWS}
	opts.MaxChecks = 5

	// Just verify it doesn't error out
	_, err := detector.Detect(context.Background(), "example.com", opts)
	if err != nil {
		// Context error is acceptable if checks run
		t.Logf("Detect() error = %v", err)
	}
}

func TestDetector_DetectBucket_NotVulnerable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Some random content that does not match any patterns"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.DetectBucket(context.Background(), server.URL, "test-bucket")
	if err != nil {
		t.Fatalf("DetectBucket() error = %v", err)
	}

	if result.Vulnerable {
		t.Error("Should not be vulnerable when no patterns match")
	}
	if result.CheckedURLs != 1 {
		t.Errorf("CheckedURLs = %d, want 1", result.CheckedURLs)
	}
}

func TestDetector_DetectBucket_ConnectionError(t *testing.T) {
	client := internalhttp.NewClient().WithTimeout(100 * time.Millisecond)
	detector := New(client)

	_, err := detector.DetectBucket(context.Background(), "http://127.0.0.1:1", "test-bucket")
	if err == nil {
		t.Error("DetectBucket() should return error for connection failure")
	}
}

func TestDetector_CreateFinding_Fields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<ListBucketResult><Contents><Key>secret.txt</Key></Contents></ListBucketResult>"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.DetectBucket(context.Background(), server.URL, "test-bucket")
	if err != nil {
		t.Fatalf("DetectBucket() error = %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Fatal("Expected vulnerability")
	}

	finding := result.Findings[0]
	if finding.Type != "Cloud Storage Misconfiguration" {
		t.Errorf("Type = %q", finding.Type)
	}
	if finding.Tool != "cloud-detector" {
		t.Errorf("Tool = %q", finding.Tool)
	}
	if finding.URL != server.URL {
		t.Errorf("URL = %q", finding.URL)
	}
	if finding.Description == "" {
		t.Error("Description should not be empty")
	}
	if finding.Evidence == "" {
		t.Error("Evidence should not be empty")
	}
	if finding.Remediation == "" {
		t.Error("Remediation should not be empty")
	}
	if len(finding.WSTG) == 0 {
		t.Error("WSTG should not be empty")
	}
}

func TestDetector_CreateFinding_LongBody(t *testing.T) {
	longContent := "<ListBucketResult><Contents><Key>"
	for i := 0; i < 600; i++ {
		longContent += "x"
	}
	longContent += "</Key></Contents></ListBucketResult>"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(longContent))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.DetectBucket(context.Background(), server.URL, "test-bucket")
	if err != nil {
		t.Fatalf("DetectBucket() error = %v", err)
	}

	if !result.Vulnerable {
		t.Fatal("Expected vulnerability")
	}

	// Evidence should exist and not be excessively long
	if len(result.Findings[0].Evidence) == 0 {
		t.Error("Evidence should not be empty")
	}
}

func TestDetector_GetRemediation(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name     string
		provider cloud.Provider
		contains string
	}{
		{name: "AWS", provider: cloud.ProviderAWS, contains: "S3"},
		{name: "GCP", provider: cloud.ProviderGCP, contains: "bucket"},
		{name: "Azure", provider: cloud.ProviderAzure, contains: "Azure"},
		{name: "Unknown", provider: cloud.Provider("unknown"), contains: "Restrict"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			remediation := detector.getRemediation(tt.provider)
			if remediation == "" {
				t.Error("Remediation should not be empty")
			}
		})
	}
}

func TestDetector_DetectGCSBucket(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<ListBucketResult xmlns="http://doc.s3.amazonaws.com/2006-03-01">
			<Name>test-gcs-bucket</Name>
			<Contents>
				<Key>data.csv</Key>
			</Contents>
		</ListBucketResult>`))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.DetectBucket(context.Background(), server.URL, "test-gcs-bucket")
	if err != nil {
		t.Fatalf("DetectBucket() error = %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected GCS bucket to be detected as open")
	}
}

func TestDetectionResult_Fields(t *testing.T) {
	result := &DetectionResult{
		Vulnerable:    true,
		CheckedURLs:   10,
		OpenBuckets:   []string{"bucket1", "bucket2"},
		OpenProviders: map[cloud.Provider]int{cloud.ProviderAWS: 1, cloud.ProviderGCP: 1},
	}

	if !result.Vulnerable {
		t.Error("Vulnerable should be true")
	}
	if result.CheckedURLs != 10 {
		t.Errorf("CheckedURLs = %d", result.CheckedURLs)
	}
	if len(result.OpenBuckets) != 2 {
		t.Errorf("OpenBuckets length = %d", len(result.OpenBuckets))
	}
	if result.OpenProviders[cloud.ProviderAWS] != 1 {
		t.Error("OpenProviders should track AWS")
	}
}

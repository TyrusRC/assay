package exposure

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	internalhttp "github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/payloads/exposure"
)

func TestNew(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	if detector == nil {
		t.Fatal("New() returned nil")
	}

	if detector.client != client {
		t.Error("client not set correctly")
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
	if opts.Timeout <= 0 {
		t.Error("Timeout should be positive")
	}
}

func TestDetector_DetectEnvFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".env") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`DB_PASSWORD=secret123
API_KEY=sk-1234567890
SECRET_KEY=supersecret
APP_ENV=production`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DetectOptions{
		MaxChecks:  10,
		Categories: []exposure.Category{exposure.CategoryConfig},
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected .env exposure to be detected")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}

	if result.Findings[0].Type != "Sensitive File Exposure" {
		t.Errorf("Expected finding type 'Sensitive File Exposure', got %s", result.Findings[0].Type)
	}
}

func TestDetector_DetectGitConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.git/config") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[core]
	repositoryformatversion = 0
	filemode = true
[remote "origin"]
	url = https://github.com/user/private-repo.git`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DetectOptions{
		MaxChecks:  10,
		Categories: []exposure.Category{exposure.CategoryVersionCtrl},
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected .git/config exposure to be detected")
	}
}

func TestDetector_DetectPrivateKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/id_rsa") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA0Z3VS5JJcds...
-----END RSA PRIVATE KEY-----`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DetectOptions{
		MaxChecks:  10,
		Categories: []exposure.Category{exposure.CategorySecret},
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected private key exposure to be detected")
	}
}

func TestDetector_DetectSQLBackup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/backup.sql") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`-- MySQL dump
CREATE TABLE users (
  id INT PRIMARY KEY,
  email VARCHAR(255),
  password VARCHAR(255)
);
INSERT INTO users VALUES (1, 'admin@test.com', 'hash123');`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DetectOptions{
		MaxChecks:  50,
		Categories: []exposure.Category{exposure.CategoryBackup},
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected SQL backup exposure to be detected")
	}
}

func TestDetector_SafeServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("404 Not Found"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DetectOptions{
		MaxChecks: 10,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability in safe server")
	}

	if len(result.Findings) != 0 {
		t.Errorf("Expected no findings, got %d", len(result.Findings))
	}
}

func TestDetector_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := detector.Detect(ctx, server.URL, DefaultOptions())

	if err == nil {
		t.Error("Expected context cancellation error")
	}
}

func TestDetector_PatternMatching(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		patterns []string
		expected bool
	}{
		{
			name:     "env file match",
			content:  "DB_PASSWORD=secret\nAPI_KEY=test123",
			patterns: []string{"DB_PASSWORD", "API_KEY"},
			expected: true,
		},
		{
			name:     "git config match",
			content:  "[core]\nrepositoryformatversion = 0",
			patterns: []string{"[core]", "repositoryformatversion"},
			expected: true,
		},
		{
			name:     "no match",
			content:  "Hello World",
			patterns: []string{"DB_PASSWORD", "API_KEY"},
			expected: false,
		},
		{
			name:     "empty patterns always match",
			content:  "anything",
			patterns: []string{},
			expected: true,
		},
	}

	client := internalhttp.NewClient()
	detector := New(client)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.matchesPatterns(tt.content, tt.patterns)
			if result != tt.expected {
				t.Errorf("matchesPatterns() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDetector_ResponseValidation(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		expected   bool
	}{
		{
			name:       "200 OK with content",
			statusCode: http.StatusOK,
			body:       "DB_PASSWORD=secret",
			expected:   true,
		},
		{
			name:       "404 Not Found",
			statusCode: http.StatusNotFound,
			body:       "Not Found",
			expected:   false,
		},
		{
			name:       "403 Forbidden",
			statusCode: http.StatusForbidden,
			body:       "Forbidden",
			expected:   false,
		},
		{
			name:       "500 Server Error",
			statusCode: http.StatusInternalServerError,
			body:       "Server Error",
			expected:   false,
		},
		{
			name:       "200 but empty body",
			statusCode: http.StatusOK,
			body:       "",
			expected:   false,
		},
		{
			name:       "200 but generic error page",
			statusCode: http.StatusOK,
			body:       "The page you requested was not found",
			expected:   false,
		},
	}

	client := internalhttp.NewClient()
	detector := New(client)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &internalhttp.Response{
				StatusCode: tt.statusCode,
				Body:       tt.body,
			}
			result := detector.isValidExposure(resp)
			if result != tt.expected {
				t.Errorf("isValidExposure() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDetector_AllCategories(t *testing.T) {
	exposedFiles := map[string]string{
		".env":                "DB_PASSWORD=secret",
		".git/config":         "[core]\nrepositoryformatversion = 0",
		"backup.sql":          "CREATE TABLE users",
		"phpinfo.php":         "PHP Version 8.0",
		"error.log":           "error: something failed",
		".idea/workspace.xml": "<?xml version=\"1.0\"?>",
		"database.db":         "SQLite format",
		"id_rsa":              "-----BEGIN RSA PRIVATE KEY-----",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if content, ok := exposedFiles[path]; ok {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(content))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DetectOptions{
		MaxChecks:     100,
		ContinueOnHit: true,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerabilities to be detected")
	}

	// We expect at least 1 finding (the detector finds files in order of payloads)
	if len(result.Findings) < 1 {
		t.Errorf("Expected at least 1 finding, got %d", len(result.Findings))
	}
}

func TestDetector_SeverityMapping(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".env") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("DB_PASSWORD=secret"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DetectOptions{
		MaxChecks: 5,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Fatal("Expected vulnerability to be detected")
	}

	// .env files should be Critical severity
	finding := result.Findings[0]
	if finding.Severity != core.SeverityCritical {
		t.Errorf("Expected critical severity for .env file, got %s", finding.Severity.String())
	}
}

func TestDetector_OWASPMapping(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".env") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("DB_PASSWORD=secret"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DetectOptions{
		MaxChecks: 5,
	})

	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	if !result.Vulnerable || len(result.Findings) == 0 {
		t.Fatal("Expected vulnerability to be detected")
	}

	finding := result.Findings[0]

	// Check OWASP mappings
	if len(finding.WSTG) == 0 {
		t.Error("Expected WSTG mapping")
	}
	if len(finding.Top10) == 0 {
		t.Error("Expected OWASP Top 10 mapping")
	}
	if len(finding.CWE) == 0 {
		t.Error("Expected CWE mapping")
	}
}

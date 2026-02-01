package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/templates"
)

func TestNewTemplateScanner(t *testing.T) {
	scanner, err := NewTemplateScanner(nil)
	if err != nil {
		t.Fatalf("NewTemplateScanner() error: %v", err)
	}
	if scanner == nil {
		t.Fatal("NewTemplateScanner() returned nil")
	}
}

func TestNewTemplateScanner_WithConfig(t *testing.T) {
	config := &TemplateScanConfig{
		Concurrency: 5,
		Verbose:     true,
	}
	scanner, err := NewTemplateScanner(config)
	if err != nil {
		t.Fatalf("NewTemplateScanner() error: %v", err)
	}
	if scanner.config.Concurrency != 5 {
		t.Errorf("Concurrency = %d, want 5", scanner.config.Concurrency)
	}
}

func TestTemplateScan_SimpleTemplate(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><head><title>Apache2 Default Page</title></head></html>"))
	}))
	defer server.Close()

	// Create template
	tmpl := &templates.Template{
		ID: "apache-detect",
		Info: templates.Info{
			Name:        "Apache Detection",
			Severity:    core.SeverityInfo,
			Description: "Detects Apache web server",
		},
		HTTP: []templates.HTTPRequest{
			{
				Method: "GET",
				Path:   []string{"/"},
				Matchers: []templates.Matcher{
					{
						Type:   "status",
						Status: []int{200},
					},
					{
						Type:  "word",
						Part:  "header",
						Words: []string{"Apache"},
					},
				},
				MatchersCondition: "and",
			},
		},
	}

	scanner, err := NewTemplateScanner(nil)
	if err != nil {
		t.Fatalf("NewTemplateScanner() error: %v", err)
	}

	target, err := core.NewTarget(server.URL)
	if err != nil {
		t.Fatalf("NewTarget() error: %v", err)
	}
	result, err := scanner.Scan(context.Background(), target, []*templates.Template{tmpl})
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if result.TemplatesRun != 1 {
		t.Errorf("TemplatesRun = %d, want 1", result.TemplatesRun)
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}
}

func TestTemplateScan_NoMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("nginx server"))
	}))
	defer server.Close()

	tmpl := &templates.Template{
		ID: "apache-only",
		Info: templates.Info{
			Name: "Apache Only",
		},
		HTTP: []templates.HTTPRequest{
			{
				Path: []string{"/"},
				Matchers: []templates.Matcher{
					{
						Type:  "word",
						Part:  "header",
						Words: []string{"Apache"},
					},
				},
			},
		},
	}

	scanner, err := NewTemplateScanner(nil)
	if err != nil {
		t.Fatalf("NewTemplateScanner() error: %v", err)
	}

	target, err := core.NewTarget(server.URL)
	if err != nil {
		t.Fatalf("NewTarget() error: %v", err)
	}
	result, err := scanner.Scan(context.Background(), target, []*templates.Template{tmpl})
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Errorf("Expected no findings, got %d", len(result.Findings))
	}
}

func TestTemplateScan_MultipleTemplates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/7.4")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	tmpls := []*templates.Template{
		{
			ID:   "php-detect",
			Info: templates.Info{Name: "PHP Detection", Severity: core.SeverityInfo},
			HTTP: []templates.HTTPRequest{
				{
					Path: []string{"/"},
					Matchers: []templates.Matcher{
						{Type: "word", Part: "header", Words: []string{"PHP"}},
					},
				},
			},
		},
		{
			ID:   "json-api",
			Info: templates.Info{Name: "JSON API", Severity: core.SeverityInfo},
			HTTP: []templates.HTTPRequest{
				{
					Path: []string{"/"},
					Matchers: []templates.Matcher{
						{Type: "word", Part: "body", Words: []string{"status"}},
					},
				},
			},
		},
		{
			ID:   "nginx-detect",
			Info: templates.Info{Name: "Nginx Detection"},
			HTTP: []templates.HTTPRequest{
				{
					Path: []string{"/"},
					Matchers: []templates.Matcher{
						{Type: "word", Part: "header", Words: []string{"nginx"}},
					},
				},
			},
		},
	}

	scanner, err := NewTemplateScanner(nil)
	if err != nil {
		t.Fatalf("NewTemplateScanner() error: %v", err)
	}

	target, err := core.NewTarget(server.URL)
	if err != nil {
		t.Fatalf("NewTarget() error: %v", err)
	}
	result, err := scanner.Scan(context.Background(), target, tmpls)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	// Should match PHP and JSON, but not nginx
	if len(result.Findings) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(result.Findings))
	}

	if result.TemplatesRun != 3 {
		t.Errorf("TemplatesRun = %d, want 3", result.TemplatesRun)
	}
}

func TestTemplateScan_EmptyTemplates(t *testing.T) {
	scanner, err := NewTemplateScanner(nil)
	if err != nil {
		t.Fatalf("NewTemplateScanner() error: %v", err)
	}

	target, err := core.NewTarget("http://example.com")
	if err != nil {
		t.Fatalf("NewTarget() error: %v", err)
	}
	result, err := scanner.Scan(context.Background(), target, []*templates.Template{})
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(result.Errors) == 0 {
		t.Error("Expected error for empty templates")
	}
}

func TestConvertToFinding(t *testing.T) {
	scanner, _ := NewTemplateScanner(nil)

	tmpl := &templates.Template{
		ID: "test-template",
		Info: templates.Info{
			Name:        "Test Vulnerability",
			Description: "A test vulnerability",
			Severity:    core.SeverityHigh,
			Remediation: "Fix the issue",
			Reference:   []string{"https://example.com/ref"},
			Classification: templates.Classification{
				CWEID: "CWE-79",
			},
		},
	}

	result := &templates.ExecutionResult{
		Matched:   true,
		MatchedAt: "http://example.com/test",
		Response:  "matched content",
		ExtractedData: map[string][]string{
			"version": {"1.0"},
		},
	}

	finding := scanner.convertToFinding(tmpl, result, "http://example.com")

	if finding.Type != "Test Vulnerability" {
		t.Errorf("Type = %q, want Test Vulnerability", finding.Type)
	}
	if finding.Severity != core.SeverityHigh {
		t.Errorf("Severity = %q, want high", finding.Severity)
	}
	if finding.Remediation != "Fix the issue" {
		t.Errorf("Remediation = %q", finding.Remediation)
	}
}

package executor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates"
)

func TestNew(t *testing.T) {
	exec := New(nil)
	if exec == nil {
		t.Fatal("New() returned nil")
	}
	if exec.matcherEngine == nil {
		t.Error("matcherEngine not initialized")
	}
	if exec.client == nil {
		t.Error("client not initialized")
	}
}

func TestNewWithConfig(t *testing.T) {
	config := &Config{
		MaxConcurrency: 5,
		Verbose:        true,
	}
	exec := New(config)
	if exec.config.MaxConcurrency != 5 {
		t.Errorf("MaxConcurrency = %d, want 5", exec.config.MaxConcurrency)
	}
}

func TestExecute_SimpleTemplate(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "value")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok", "version": "1.0"}`))
	}))
	defer server.Close()

	// Create template
	tmpl := &templates.Template{
		ID: "test-template",
		Info: templates.Info{
			Name:     "Test Template",
			Severity: core.SeverityInfo,
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
						Part:  "body",
						Words: []string{"ok"},
					},
				},
				MatchersCondition: "and",
			},
		},
	}

	exec := New(nil)
	results, err := exec.Execute(context.Background(), tmpl, server.URL)
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("No results returned")
	}

	if !results[0].Matched {
		t.Error("Expected template to match")
	}
}

func TestExecute_NoMatch(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	}))
	defer server.Close()

	tmpl := &templates.Template{
		ID: "test-no-match",
		Info: templates.Info{
			Name: "Test No Match",
		},
		HTTP: []templates.HTTPRequest{
			{
				Path: []string{"/"},
				Matchers: []templates.Matcher{
					{
						Type:   "status",
						Status: []int{200},
					},
				},
			},
		},
	}

	exec := New(nil)
	results, err := exec.Execute(context.Background(), tmpl, server.URL)
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	if len(results) > 0 && results[0].Matched {
		t.Error("Expected no match for 404 response")
	}
}

func TestExecute_RegexMatcher(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`Version: 2.5.1`))
	}))
	defer server.Close()

	tmpl := &templates.Template{
		ID: "test-regex",
		Info: templates.Info{
			Name: "Test Regex",
		},
		HTTP: []templates.HTTPRequest{
			{
				Path: []string{"/"},
				Matchers: []templates.Matcher{
					{
						Type:  "regex",
						Part:  "body",
						Regex: []string{`Version:\s+(\d+\.\d+\.\d+)`},
					},
				},
			},
		},
	}

	exec := New(nil)
	results, err := exec.Execute(context.Background(), tmpl, server.URL)
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	if len(results) == 0 || !results[0].Matched {
		t.Error("Expected regex to match")
	}
}

func TestExecute_WordMatcher(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`Welcome to Apache Tomcat`))
	}))
	defer server.Close()

	tmpl := &templates.Template{
		ID: "test-word",
		Info: templates.Info{
			Name: "Test Word",
		},
		HTTP: []templates.HTTPRequest{
			{
				Path: []string{"/"},
				Matchers: []templates.Matcher{
					{
						Type:      "word",
						Part:      "body",
						Words:     []string{"Apache", "Tomcat"},
						Condition: "and",
					},
				},
			},
		},
	}

	exec := New(nil)
	results, err := exec.Execute(context.Background(), tmpl, server.URL)
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	if len(results) == 0 || !results[0].Matched {
		t.Error("Expected word matcher to match")
	}
}

func TestExecute_Extractors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Version", "1.2.3")
		w.Write([]byte(`{"name": "test", "id": 123}`))
	}))
	defer server.Close()

	tmpl := &templates.Template{
		ID: "test-extractor",
		Info: templates.Info{
			Name: "Test Extractor",
		},
		HTTP: []templates.HTTPRequest{
			{
				Path: []string{"/"},
				Matchers: []templates.Matcher{
					{
						Type:   "status",
						Status: []int{200},
					},
				},
				Extractors: []templates.Extractor{
					{
						Type: "kval",
						Name: "version",
						KVal: []string{"X-Version"},
					},
					{
						Type: "json",
						Name: "app_name",
						JSON: []string{"name"},
					},
				},
			},
		},
	}

	exec := New(nil)
	results, err := exec.Execute(context.Background(), tmpl, server.URL)
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("No results")
	}

	if results[0].ExtractedData == nil {
		t.Fatal("No extracted data")
	}

	if v, ok := results[0].ExtractedData["version"]; !ok || len(v) == 0 || v[0] != "1.2.3" {
		t.Errorf("version extraction failed: got %v", v)
	}

	if v, ok := results[0].ExtractedData["app_name"]; !ok || len(v) == 0 || v[0] != "test" {
		t.Errorf("app_name extraction failed: got %v", v)
	}
}

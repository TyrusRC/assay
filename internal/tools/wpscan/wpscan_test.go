package wpscan

import (
	"strings"
	"testing"

	"github.com/TyrusRC/assay/internal/tools"
)

func TestBuildArgs(t *testing.T) {
	w := &WPScan{binaryPath: "/usr/bin/wpscan", options: defaultOptions()}
	req := tools.NewToolRequest("http://example.com")
	req.WithProxy("http://127.0.0.1:8080")

	args := w.BuildArgs(req)
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "--url http://example.com") {
		t.Error("missing target URL")
	}
	if !strings.Contains(joined, "--format json") {
		t.Error("missing json format")
	}
	if !strings.Contains(joined, "--proxy http://127.0.0.1:8080") {
		t.Error("missing proxy")
	}
}

func TestParseJSONOutput(t *testing.T) {
	w := &WPScan{binaryPath: "/usr/bin/wpscan"}

	jsonData := []byte(`{
		"version": {
			"number": "6.0",
			"status": "insecure",
			"vulnerabilities": [
				{"title": "WordPress 6.0 - SQL Injection in WP_Query", "fixed_in": "6.0.1", "references": {"url": ["https://example.com"]}}
			]
		},
		"plugins": {
			"contact-form-7": {
				"slug": "contact-form-7",
				"version": {"number": "5.1.3"},
				"vulnerabilities": [
					{"title": "Contact Form 7 - Unrestricted File Upload", "fixed_in": "5.3.2"}
				]
			}
		}
	}`)

	result := w.ParseJSONOutput(jsonData, "http://example.com")
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}

	coreVuln := result.Findings[0]
	if !strings.Contains(coreVuln.Description, "WordPress Core 6.0") {
		t.Errorf("expected core finding, got %s", coreVuln.Description)
	}

	pluginVuln := result.Findings[1]
	if !strings.Contains(pluginVuln.Description, "contact-form-7") {
		t.Errorf("expected plugin finding, got %s", pluginVuln.Description)
	}
}

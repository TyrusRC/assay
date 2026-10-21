package nikto

import (
	"strings"
	"testing"

	"github.com/TyrusRC/assay/internal/tools"
)

func TestBuildArgs(t *testing.T) {
	n := &Nikto{binaryPath: "/usr/bin/nikto", options: defaultOptions()}
	req := tools.NewToolRequest("http://example.com")
	req.WithProxy("http://127.0.0.1:8080")

	args := n.BuildArgs(req)
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "-h http://example.com") {
		t.Error("missing target host")
	}
	if !strings.Contains(joined, "-Format json") {
		t.Error("missing json format")
	}
	if !strings.Contains(joined, "-useproxy http://127.0.0.1:8080") {
		t.Error("missing proxy")
	}
}

func TestParseOutput(t *testing.T) {
	n := &Nikto{binaryPath: "/usr/bin/nikto"}

	output := `+ OSVDB-3092: /admin/: This might be interesting.
+ OSVDB-3268: /icons/: Directory listing found.
+ Server: Apache/2.4.49 (vulnerable to path traversal)`
	result := n.ParseOutput(output, "http://example.com")
	if len(result.Findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(result.Findings))
	}
}

func TestParseJSONOutput(t *testing.T) {
	n := &Nikto{binaryPath: "/usr/bin/nikto"}

	jsonData := []byte(`{
		"host": "example.com",
		"ip": "1.2.3.4",
		"port": "80",
		"vulnerabilities": [
			{"id": "1", "OSVDB": "3092", "method": "GET", "msg": "Admin page found", "url": "/admin/"}
		]
	}`)

	result := n.ParseJSONOutput(jsonData, "http://example.com")
	if !result.HasFindings() {
		t.Fatal("expected findings from JSON output")
	}
}

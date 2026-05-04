package nuclei

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/tools"
)

func TestNew_DoesNotPanicWhenBinaryAbsent(t *testing.T) {
	// Construction must succeed even when the binary is missing —
	// the scanner constructs all tool wrappers eagerly during boot.
	n := New()
	if n == nil {
		t.Fatal("New() returned nil")
	}
	if n.Name() != "nuclei" {
		t.Fatalf("Name() = %q, want nuclei", n.Name())
	}
}

func TestExecute_ReturnsErrorWhenUnavailable(t *testing.T) {
	n := &Nuclei{options: defaultOptions()} // no binaryPath
	if n.IsAvailable() {
		t.Fatal("IsAvailable() should be false when binaryPath is empty")
	}
	res, err := n.Execute(context.Background(), tools.NewToolRequest("https://example.com"))
	if err == nil {
		t.Fatal("expected error from Execute when binary unavailable")
	}
	if res == nil {
		t.Fatal("expected non-nil ToolResult even on unavailable binary")
	}
	if res.IsSuccess() {
		t.Fatal("ToolResult should not be marked success when binary missing")
	}
}

func TestHealthCheck_FailsWhenUnavailable(t *testing.T) {
	n := &Nuclei{options: defaultOptions()}
	if err := n.HealthCheck(); err == nil {
		t.Fatal("HealthCheck must fail when binary missing")
	}
}

func TestBuildArgs_IncludesCoreFlags(t *testing.T) {
	n := &Nuclei{options: defaultOptions()}
	req := tools.NewToolRequest("https://example.com/api")
	args := n.BuildArgs(req)

	must := []string{"-target", "https://example.com/api", "-jsonl", "-no-color", "-silent"}
	for _, m := range must {
		if !contains(args, m) {
			t.Errorf("BuildArgs missing %q. Got: %v", m, args)
		}
	}
}

func TestBuildArgs_AppliesOptions(t *testing.T) {
	n := &Nuclei{
		options: Options{
			TemplatePaths: []string{"/tmp/templates", "/extra.yaml"},
			Tags:          []string{"cve", "rce"},
			Severity:      []string{"high", "critical"},
			Concurrency:   50,
			RateLimit:     100,
			Timeout:       15,
			Retries:       2,
			Silent:        true,
		},
	}
	req := tools.NewToolRequest("https://example.com").
		WithHeaders(map[string]string{"Authorization": "Bearer t"}).
		WithCookies("session=abc").
		WithProxy("http://127.0.0.1:8080").
		WithCustomArgs("-debug")

	args := n.BuildArgs(req)
	joined := strings.Join(args, " ")

	for _, want := range []string{
		"-t /tmp/templates",
		"-t /extra.yaml",
		"-tags cve,rce",
		"-severity high,critical",
		"-c 50",
		"-rl 100",
		"-timeout 15",
		"-retries 2",
		"-H Authorization: Bearer t",
		"-H Cookie: session=abc",
		"-proxy http://127.0.0.1:8080",
		"-debug",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected args to contain %q, got: %s", want, joined)
		}
	}
}

func TestMapSeverity(t *testing.T) {
	cases := map[string]core.Severity{
		"critical":      core.SeverityCritical,
		"high":          core.SeverityHigh,
		"medium":        core.SeverityMedium,
		"low":           core.SeverityLow,
		"info":          core.SeverityInfo,
		"informational": core.SeverityInfo,
		"INFO":          core.SeverityInfo,
		" High ":        core.SeverityHigh,
		"unknown":       core.SeverityInfo, // fallback
		"":              core.SeverityInfo,
	}
	for in, want := range cases {
		if got := mapSeverity(in); got != want {
			t.Errorf("mapSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseJSONL_HandlesEmpty(t *testing.T) {
	if got := ParseJSONL(""); len(got) != 0 {
		t.Fatalf("expected 0 findings on empty input, got %d", len(got))
	}
	if got := ParseJSONL("\n\n\n"); len(got) != 0 {
		t.Fatalf("expected 0 findings on whitespace-only input, got %d", len(got))
	}
}

func TestParseJSONL_SkipsNonJSONLines(t *testing.T) {
	raw := "[INF] Banner output line\nWARN: something\n"
	if got := ParseJSONL(raw); len(got) != 0 {
		t.Fatalf("expected 0 findings on non-JSON input, got %d", len(got))
	}
}

func TestParseJSONL_SkipsMalformedJSON(t *testing.T) {
	raw := `{"template-id": "broken"` // unterminated
	if got := ParseJSONL(raw); len(got) != 0 {
		t.Fatalf("expected 0 findings on malformed JSON, got %d", len(got))
	}
}

func TestParseJSONL_ParsesValidFindings(t *testing.T) {
	raw := `{"template-id":"cve-2021-44228","template-url":"https://templates/cve.yaml","type":"http","host":"https://example.com","matched-at":"https://example.com/api?q=x","info":{"name":"Apache Log4j RCE","severity":"critical","description":"Log4j JNDI lookup RCE","tags":["cve","rce","log4j"],"reference":["https://nvd.nist.gov/cve-2021-44228"],"remediation":"Upgrade Log4j","classification":{"cve-id":["CVE-2021-44228"],"cwe-id":["CWE-502"],"cvss-score":10.0}},"extracted-results":["jndi-payload-fired"],"curl-command":"curl ..."}
{"template-id":"weak-tls","type":"ssl","host":"example.com:443","matched-at":"example.com:443","info":{"name":"Weak TLS","severity":"medium","tags":["ssl","misconfig"]}}
not-json-line
`

	findings := ParseJSONL(raw)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	f1 := findings[0]
	if f1.Title != "Apache Log4j RCE" {
		t.Errorf("Title = %q, want Apache Log4j RCE", f1.Title)
	}
	if f1.Severity != core.SeverityCritical {
		t.Errorf("Severity = %q, want critical", f1.Severity)
	}
	if f1.URL != "https://example.com/api?q=x" {
		t.Errorf("URL = %q, want matched-at", f1.URL)
	}
	if f1.Tool != "nuclei" {
		t.Errorf("Tool = %q, want nuclei", f1.Tool)
	}
	if f1.CVSS != 10.0 {
		t.Errorf("CVSS = %v, want 10.0", f1.CVSS)
	}
	if len(f1.CWE) != 1 || f1.CWE[0] != "CWE-502" {
		t.Errorf("CWE = %v, want [CWE-502]", f1.CWE)
	}
	if f1.Evidence != "jndi-payload-fired" {
		t.Errorf("Evidence = %q, want jndi-payload-fired", f1.Evidence)
	}
	if cves, ok := f1.Metadata["nuclei.cve"].([]string); !ok || len(cves) != 1 || cves[0] != "CVE-2021-44228" {
		t.Errorf("Metadata[nuclei.cve] = %v, want [CVE-2021-44228]", f1.Metadata["nuclei.cve"])
	}
	if id, ok := f1.Metadata["nuclei.template-id"].(string); !ok || id != "cve-2021-44228" {
		t.Errorf("Metadata[nuclei.template-id] = %v, want cve-2021-44228", f1.Metadata["nuclei.template-id"])
	}

	f2 := findings[1]
	if f2.Title != "Weak TLS" || f2.Severity != core.SeverityMedium {
		t.Errorf("second finding wrong: %+v", f2)
	}
	if f2.URL != "example.com:443" {
		t.Errorf("URL fallback to matched-at failed: %q", f2.URL)
	}
}

func TestParseJSONL_FallsBackToTemplateIDWhenNameMissing(t *testing.T) {
	raw := `{"template-id":"my-template","host":"https://x","info":{"severity":"low"}}`
	findings := ParseJSONL(raw)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Title != "my-template" {
		t.Errorf("Title fallback to template-id failed: %q", findings[0].Title)
	}
	if findings[0].URL != "https://x" {
		t.Errorf("URL fallback to host failed: %q", findings[0].URL)
	}
}

func TestParseJSONL_DropsRecordsWithoutAnyIdentity(t *testing.T) {
	raw := `{"info":{"severity":"low"}}`
	if got := ParseJSONL(raw); len(got) != 0 {
		t.Fatalf("expected sparse record dropped, got %d", len(got))
	}
}

// --- Tool interface conformance ---

func TestNuclei_ImplementsToolInterface(t *testing.T) {
	var _ tools.Tool = (*Nuclei)(nil)
}

func TestExecute_RespectsContextCancel(t *testing.T) {
	// We can't run the real binary in unit tests, but we can confirm
	// that an immediately-cancelled context produces a quick error.
	n := &Nuclei{options: defaultOptions()} // no binary
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	time.Sleep(2 * time.Millisecond)
	_, err := n.Execute(ctx, tools.NewToolRequest("https://example.com"))
	if err == nil {
		t.Fatal("expected error from Execute on cancelled context with missing binary")
	}
}

// contains returns true if needle appears as a discrete element in haystack.
func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

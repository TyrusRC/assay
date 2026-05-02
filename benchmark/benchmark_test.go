package benchmark

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/scanner"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates/parser"
)

// BenchmarkParseTemplates benchmarks template parsing speed
func BenchmarkParseTemplates(b *testing.B) {
	templatesDir := "/tmp/nuclei-templates/http/technologies"
	if _, err := os.Stat(templatesDir); os.IsNotExist(err) {
		b.Skip("Nuclei templates not found")
	}

	p := parser.New()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = p.ParseDirectory(templatesDir)
	}
}

// BenchmarkSKWSExecution benchmarks SKWS template execution
func BenchmarkSKWSExecution(b *testing.B) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41")
		w.Header().Set("X-Powered-By", "PHP/7.4")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head><title>Test Page</title></head><body>Welcome</body></html>`))
	}))
	defer server.Close()

	// Create templates
	tmpls := createBenchmarkTemplates()

	s, _ := scanner.NewTemplateScanner(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		target, _ := core.NewTarget(server.URL)
		_, _ = s.Scan(context.Background(), target, tmpls)
	}
}

// BenchmarkNucleiExecution benchmarks nuclei execution (if available)
func BenchmarkNucleiExecution(b *testing.B) {
	nucleiPath, err := exec.LookPath("nuclei")
	if err != nil {
		nucleiPath = os.Getenv("HOME") + "/go/bin/nuclei"
		if _, err := os.Stat(nucleiPath); os.IsNotExist(err) {
			b.Skip("Nuclei not found")
		}
	}

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><title>Test</title></html>`))
	}))
	defer server.Close()

	// Create a simple template file
	tmplContent := `id: bench-apache-detect
info:
  name: Apache Detection
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        part: header
        words:
          - "Apache"
`
	tmpDir := b.TempDir()
	tmplPath := filepath.Join(tmpDir, "bench.yaml")
	os.WriteFile(tmplPath, []byte(tmplContent), 0644)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cmd := exec.Command(nucleiPath, "-t", tmplPath, "-u", server.URL, "-silent", "-nc")
		cmd.Run()
	}
}

func createBenchmarkTemplates() []*templates.Template {
	return []*templates.Template{
		{
			ID:   "apache-detect",
			Info: templates.Info{Name: "Apache Detection", Severity: core.SeverityInfo},
			HTTP: []templates.HTTPRequest{
				{
					Method: "GET",
					Path:   []string{"/"},
					Matchers: []templates.Matcher{
						{Type: "word", Part: "header", Words: []string{"Apache"}},
					},
				},
			},
		},
		{
			ID:   "php-detect",
			Info: templates.Info{Name: "PHP Detection", Severity: core.SeverityInfo},
			HTTP: []templates.HTTPRequest{
				{
					Method: "GET",
					Path:   []string{"/"},
					Matchers: []templates.Matcher{
						{Type: "word", Part: "header", Words: []string{"PHP"}},
					},
				},
			},
		},
		{
			ID:   "title-detect",
			Info: templates.Info{Name: "Title Detection", Severity: core.SeverityInfo},
			HTTP: []templates.HTTPRequest{
				{
					Method: "GET",
					Path:   []string{"/"},
					Matchers: []templates.Matcher{
						{Type: "regex", Part: "body", Regex: []string{`<title>([^<]+)</title>`}},
					},
				},
			},
		},
	}
}

// TestComparePerformance runs a performance comparison between SKWS and nuclei
func TestComparePerformance(t *testing.T) {
	nucleiPath, err := exec.LookPath("nuclei")
	if err != nil {
		nucleiPath = os.Getenv("HOME") + "/go/bin/nuclei"
		if _, err := os.Stat(nucleiPath); os.IsNotExist(err) {
			t.Skip("Nuclei not found")
		}
	}

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41")
		w.Header().Set("X-Powered-By", "PHP/7.4")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Test Application</title></head>
<body>
<h1>Welcome to the test server</h1>
<p>Version: 1.0.0</p>
</body>
</html>`))
	}))
	defer server.Close()

	// Create template files for nuclei
	tmpDir := t.TempDir()
	templateContent := `id: bench-test
info:
  name: Benchmark Test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        part: header
        words:
          - "Apache"
      - type: status
        status:
          - 200
    matchers-condition: and
`
	tmplPath := filepath.Join(tmpDir, "bench.yaml")
	os.WriteFile(tmplPath, []byte(templateContent), 0644)

	iterations := 10

	// Benchmark SKWS
	t.Log("=== SKWS Template Scanner ===")
	skwsTimes := make([]time.Duration, iterations)
	s, _ := scanner.NewTemplateScanner(nil)
	p := parser.New()
	tmpl, _ := p.ParseFile(tmplPath)

	for i := 0; i < iterations; i++ {
		start := time.Now()
		target, _ := core.NewTarget(server.URL)
		result, _ := s.Scan(context.Background(), target, []*templates.Template{tmpl})
		skwsTimes[i] = time.Since(start)
		if i == 0 {
			t.Logf("  Findings: %d, Match: %v", len(result.Findings), len(result.Findings) > 0)
		}
	}

	avgSKWS := averageDuration(skwsTimes)
	t.Logf("  Average time: %v", avgSKWS)
	t.Logf("  Min: %v, Max: %v", minDuration(skwsTimes), maxDuration(skwsTimes))

	// Benchmark Nuclei
	t.Log("\n=== Nuclei ===")
	nucleiTimes := make([]time.Duration, iterations)

	// Warmup nuclei (first run is always slow due to loading)
	warmupCmd := exec.Command(nucleiPath, "-t", tmplPath, "-u", server.URL, "-silent", "-nc", "-no-interactsh", "-no-color")
	warmupCmd.Run()

	for i := 0; i < iterations; i++ {
		start := time.Now()
		cmd := exec.Command(nucleiPath, "-t", tmplPath, "-u", server.URL, "-silent", "-nc", "-no-interactsh", "-no-color")
		output, _ := cmd.CombinedOutput()
		nucleiTimes[i] = time.Since(start)
		if i == 0 {
			out := strings.TrimSpace(string(output))
			if out != "" {
				t.Logf("  Output: %s", out)
			} else {
				t.Logf("  (no matches)")
			}
		}
	}

	avgNuclei := averageDuration(nucleiTimes)
	t.Logf("  Average time: %v", avgNuclei)
	t.Logf("  Min: %v, Max: %v", minDuration(nucleiTimes), maxDuration(nucleiTimes))

	// Comparison
	t.Log("\n=== Performance Comparison ===")
	if avgSKWS < avgNuclei {
		speedup := float64(avgNuclei) / float64(avgSKWS)
		t.Logf("  SKWS is %.2fx faster than Nuclei", speedup)
	} else {
		speedup := float64(avgSKWS) / float64(avgNuclei)
		t.Logf("  Nuclei is %.2fx faster than SKWS", speedup)
	}
}

// TestMultiTemplateComparison compares with multiple templates
func TestMultiTemplateComparison(t *testing.T) {
	templatesDir := "/tmp/nuclei-templates/http/technologies"
	if _, err := os.Stat(templatesDir); os.IsNotExist(err) {
		t.Skip("Nuclei templates not found")
	}

	nucleiPath, err := exec.LookPath("nuclei")
	if err != nil {
		nucleiPath = os.Getenv("HOME") + "/go/bin/nuclei"
		if _, err := os.Stat(nucleiPath); os.IsNotExist(err) {
			t.Skip("Nuclei not found")
		}
	}

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/8.0.3")
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html><html><head><title>Test</title></head><body>Test</body></html>`))
	}))
	defer server.Close()

	// Load templates
	p := parser.New()
	tmpls, err := p.ParseDirectory(templatesDir)
	if err != nil {
		t.Fatalf("Failed to load templates: %v", err)
	}

	// Limit to first 50 templates for fair comparison
	if len(tmpls) > 50 {
		tmpls = tmpls[:50]
	}
	t.Logf("Testing with %d templates", len(tmpls))

	// Create temp dir with templates for nuclei
	tmpDir := t.TempDir()
	count := 0
	for _, tmpl := range tmpls {
		if tmpl.Path != "" {
			content, _ := os.ReadFile(tmpl.Path)
			destPath := filepath.Join(tmpDir, fmt.Sprintf("tmpl_%d.yaml", count))
			os.WriteFile(destPath, content, 0644)
			count++
		}
	}

	// Test SKWS
	t.Log("\n=== SKWS with multiple templates ===")
	s, _ := scanner.NewTemplateScanner(&scanner.TemplateScanConfig{
		Concurrency: 10,
	})

	start := time.Now()
	target, _ := core.NewTarget(server.URL)
	result, _ := s.Scan(context.Background(), target, tmpls)
	skwsTime := time.Since(start)
	t.Logf("  Time: %v", skwsTime)
	t.Logf("  Templates run: %d", result.TemplatesRun)
	t.Logf("  Findings: %d", len(result.Findings))

	// Test Nuclei
	t.Log("\n=== Nuclei with multiple templates ===")
	start = time.Now()
	cmd := exec.Command(nucleiPath, "-t", tmpDir, "-u", server.URL, "-silent", "-nc", "-no-interactsh", "-c", "10")
	output, _ := cmd.CombinedOutput()
	nucleiTime := time.Since(start)

	nucleiMatches := 0
	for _, line := range strings.Split(string(output), "\n") {
		if strings.TrimSpace(line) != "" {
			nucleiMatches++
		}
	}
	t.Logf("  Time: %v", nucleiTime)
	t.Logf("  Findings: %d", nucleiMatches)

	// Comparison
	t.Log("\n=== Multi-Template Performance Comparison ===")
	if skwsTime < nucleiTime {
		speedup := float64(nucleiTime) / float64(skwsTime)
		t.Logf("  SKWS is %.2fx faster than Nuclei", speedup)
	} else {
		speedup := float64(skwsTime) / float64(nucleiTime)
		t.Logf("  Nuclei is %.2fx faster than SKWS", speedup)
	}
}

func averageDuration(durations []time.Duration) time.Duration {
	var total time.Duration
	for _, d := range durations {
		total += d
	}
	return total / time.Duration(len(durations))
}

func minDuration(durations []time.Duration) time.Duration {
	min := durations[0]
	for _, d := range durations[1:] {
		if d < min {
			min = d
		}
	}
	return min
}

func maxDuration(durations []time.Duration) time.Duration {
	max := durations[0]
	for _, d := range durations[1:] {
		if d > max {
			max = d
		}
	}
	return max
}

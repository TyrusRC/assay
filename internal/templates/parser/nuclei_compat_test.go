package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/swiss-knife-for-web-security/skws/internal/templates"
)

var _ = templates.Template{} // ensure import is used

// TestParseNucleiTemplates tests parsing real nuclei templates
func TestParseNucleiTemplates(t *testing.T) {
	templatesDir := "/tmp/nuclei-templates"

	// Check if templates exist
	if _, err := os.Stat(templatesDir); os.IsNotExist(err) {
		t.Skip("Nuclei templates not found at /tmp/nuclei-templates")
	}

	p := New()

	var totalFiles int
	var parsedOK int
	var parseFailed int
	var httpTemplates int
	var skipped int
	errors := make(map[string]int)

	// Walk through templates
	err := filepath.Walk(templatesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Skip non-YAML files
		if info.IsDir() || !isYAMLFile(path) {
			return nil
		}

		// Skip workflow, helpers, and profiles directories
		relPath, _ := filepath.Rel(templatesDir, path)
		if strings.HasPrefix(relPath, "workflows") ||
			strings.HasPrefix(relPath, "helpers") ||
			strings.HasPrefix(relPath, "profiles") ||
			strings.HasPrefix(relPath, ".") {
			skipped++
			return nil
		}

		totalFiles++

		tmpl, err := p.ParseFile(path)
		if err != nil {
			parseFailed++
			// Categorize error
			errType := categorizeError(err)
			errors[errType]++
			return nil
		}

		parsedOK++
		if len(tmpl.HTTP) > 0 {
			httpTemplates++
		}

		return nil
	})

	if err != nil {
		t.Fatalf("Walk error: %v", err)
	}

	// Report results
	t.Logf("\n=== Nuclei Template Parsing Results ===")
	t.Logf("Total YAML files: %d", totalFiles)
	t.Logf("Skipped (workflows/helpers): %d", skipped)
	t.Logf("Parsed successfully: %d (%.1f%%)", parsedOK, float64(parsedOK)/float64(totalFiles)*100)
	t.Logf("Parse failed: %d (%.1f%%)", parseFailed, float64(parseFailed)/float64(totalFiles)*100)
	t.Logf("HTTP templates: %d", httpTemplates)

	if len(errors) > 0 {
		t.Logf("\nError breakdown:")
		for errType, count := range errors {
			t.Logf("  %s: %d", errType, count)
		}
	}

	// We should be able to parse at least 70% of templates
	successRate := float64(parsedOK) / float64(totalFiles) * 100
	if successRate < 70 {
		t.Errorf("Parse success rate too low: %.1f%% (want >= 70%%)", successRate)
	}
}

func categorizeError(err error) string {
	errStr := err.Error()

	if strings.Contains(errStr, "template ID is required") {
		return "missing-id"
	}
	if strings.Contains(errStr, "template name is required") {
		return "missing-name"
	}
	if strings.Contains(errStr, "protocol handler") {
		return "missing-protocol"
	}
	if strings.Contains(errStr, "matcher") {
		return "invalid-matcher"
	}
	if strings.Contains(errStr, "decode YAML") {
		return "yaml-decode-error"
	}

	return "other"
}

// BenchmarkParseTemplate benchmarks template parsing speed
func BenchmarkParseTemplate(b *testing.B) {
	templatesDir := "/tmp/nuclei-templates/http"

	if _, err := os.Stat(templatesDir); os.IsNotExist(err) {
		b.Skip("Nuclei templates not found")
	}

	// Find first valid template
	var templatePath string
	filepath.Walk(templatesDir, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() && isYAMLFile(path) && templatePath == "" {
			templatePath = path
			return filepath.SkipDir
		}
		return nil
	})

	if templatePath == "" {
		b.Fatal("No template found")
	}

	data, err := os.ReadFile(templatePath)
	if err != nil {
		b.Fatal(err)
	}

	p := New()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = p.ParseBytes(data)
	}
}

// BenchmarkParseDirectory benchmarks directory parsing
func BenchmarkParseDirectory(b *testing.B) {
	templatesDir := "/tmp/nuclei-templates/http/technologies"

	if _, err := os.Stat(templatesDir); os.IsNotExist(err) {
		b.Skip("Nuclei templates not found")
	}

	p := New()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = p.ParseDirectory(templatesDir)
	}
}

// TestParseSpecificCategories tests specific template categories
func TestParseSpecificCategories(t *testing.T) {
	categories := []string{
		"/tmp/nuclei-templates/http/technologies",
		"/tmp/nuclei-templates/http/misconfiguration",
		"/tmp/nuclei-templates/http/cves",
		"/tmp/nuclei-templates/http/vulnerabilities",
		"/tmp/nuclei-templates/http/exposures",
	}

	p := New()

	for _, category := range categories {
		if _, err := os.Stat(category); os.IsNotExist(err) {
			continue
		}

		var total, ok, failed int

		filepath.Walk(category, func(path string, info os.FileInfo, err error) error {
			if info.IsDir() || !isYAMLFile(path) {
				return nil
			}

			total++
			if _, err := p.ParseFile(path); err != nil {
				failed++
			} else {
				ok++
			}
			return nil
		})

		categoryName := filepath.Base(category)
		t.Logf("%s: %d/%d parsed (%.1f%%)",
			categoryName, ok, total, float64(ok)/float64(total)*100)
	}
}

// TestParseSampleTemplates parses sample templates for detailed analysis
func TestParseSampleTemplates(t *testing.T) {
	sampleTemplates := []string{
		"/tmp/nuclei-templates/http/technologies/apache/apache-detect.yaml",
		"/tmp/nuclei-templates/http/technologies/nginx/nginx-version.yaml",
		"/tmp/nuclei-templates/http/misconfiguration/http-missing-security-headers.yaml",
	}

	p := New()

	for _, path := range sampleTemplates {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}

		tmpl, err := p.ParseFile(path)
		if err != nil {
			t.Logf("FAIL: %s - %v", filepath.Base(path), err)
			continue
		}

		t.Logf("OK: %s (ID: %s, HTTP requests: %d, Matchers: %d)",
			filepath.Base(path),
			tmpl.ID,
			len(tmpl.HTTP),
			countMatchers(tmpl))
	}
}

func countMatchers(tmpl *templates.Template) int {
	count := 0
	for _, req := range tmpl.HTTP {
		count += len(req.Matchers)
	}
	return count
}

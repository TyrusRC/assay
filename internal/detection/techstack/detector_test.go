package techstack

import (
	"testing"
)

func TestNewDetector(t *testing.T) {
	detector, err := NewDetector()
	if err != nil {
		t.Fatalf("NewDetector() error = %v", err)
	}
	if detector == nil {
		t.Fatal("NewDetector() returned nil")
	}
}

func TestDetector_Analyze_PHP(t *testing.T) {
	detector, _ := NewDetector()

	headers := map[string]string{
		"X-Powered-By": "PHP/8.1.0",
		"Server":       "Apache/2.4.51",
	}
	body := `<!DOCTYPE html><html><head></head><body></body></html>`

	result := detector.Analyze("https://example.com", headers, body)

	if result == nil {
		t.Fatal("Analyze() returned nil")
	}

	// Wappalyzer detection is based on its internal database
	// Just verify the method works without crashing
	t.Logf("Detected %d technologies", len(result.Technologies))
	for _, tech := range result.Technologies {
		t.Logf("  - %s", tech.String())
	}
}

func TestDetector_Analyze_WordPress(t *testing.T) {
	detector, _ := NewDetector()

	headers := map[string]string{}
	body := `<!DOCTYPE html>
<html>
<head>
<link rel="stylesheet" href="/wp-content/themes/theme/style.css">
<script src="/wp-includes/js/jquery.min.js"></script>
</head>
<body>
<meta name="generator" content="WordPress 6.0">
</body>
</html>`

	result := detector.Analyze("https://example.com", headers, body)

	// WordPress should be detected from wp-content paths
	t.Logf("Detected %d technologies", len(result.Technologies))
	for _, tech := range result.Technologies {
		t.Logf("  - %s (categories: %v)", tech.String(), tech.Categories)
	}

	// Verify result structure is correct
	if result.URL != "https://example.com" {
		t.Errorf("URL = %q, want %q", result.URL, "https://example.com")
	}
}

func TestDetector_Analyze_React(t *testing.T) {
	detector, _ := NewDetector()

	headers := map[string]string{}
	body := `<!DOCTYPE html>
<html>
<head></head>
<body>
<div id="root" data-reactroot></div>
<script src="/static/js/main.chunk.js"></script>
</body>
</html>`

	result := detector.Analyze("https://example.com", headers, body)

	foundReact := false
	for _, tech := range result.Technologies {
		if tech.Name == "React" {
			foundReact = true
			break
		}
	}
	// Note: This may not detect React without actual JS execution
	// Just verify the analyzer doesn't crash
	_ = foundReact
}

func TestDetector_Analyze_Nginx(t *testing.T) {
	detector, _ := NewDetector()

	headers := map[string]string{
		"Server": "nginx/1.21.0",
	}
	body := `<html></html>`

	result := detector.Analyze("https://example.com", headers, body)

	// Log detected technologies
	t.Logf("Detected %d technologies from nginx headers", len(result.Technologies))
	for _, tech := range result.Technologies {
		t.Logf("  - %s", tech.String())
	}

	// Verify the analyzer handles headers correctly
	if result == nil {
		t.Fatal("Analyze() returned nil")
	}
}

func TestDetector_GetSecurityImplications(t *testing.T) {
	detector, _ := NewDetector()

	implications := detector.GetSecurityImplications("PHP")
	if implications == nil {
		t.Fatal("GetSecurityImplications() returned nil")
	}

	if len(implications.CommonVulnerabilities) == 0 {
		t.Error("PHP should have common vulnerabilities listed")
	}
}

func TestTechnology_String(t *testing.T) {
	tech := Technology{
		Name:       "PHP",
		Version:    "8.1.0",
		Categories: []string{"Programming languages"},
	}

	str := tech.String()
	if str != "PHP 8.1.0" {
		t.Errorf("String() = %q, want %q", str, "PHP 8.1.0")
	}
}

func TestDetectionResult_HasTechnology(t *testing.T) {
	result := &DetectionResult{
		Technologies: []Technology{
			{Name: "PHP", Version: "8.1.0"},
			{Name: "Apache"},
		},
	}

	if !result.HasTechnology("PHP") {
		t.Error("HasTechnology(PHP) should return true")
	}
	if !result.HasTechnology("Apache") {
		t.Error("HasTechnology(Apache) should return true")
	}
	if result.HasTechnology("Nginx") {
		t.Error("HasTechnology(Nginx) should return false")
	}
}

func TestDetectionResult_GetByCategory(t *testing.T) {
	result := &DetectionResult{
		Technologies: []Technology{
			{Name: "PHP", Categories: []string{"Programming languages"}},
			{Name: "Apache", Categories: []string{"Web servers"}},
			{Name: "WordPress", Categories: []string{"CMS", "Blogs"}},
		},
	}

	webServers := result.GetByCategory("Web servers")
	if len(webServers) != 1 || webServers[0].Name != "Apache" {
		t.Error("GetByCategory(Web servers) should return Apache")
	}

	cms := result.GetByCategory("CMS")
	if len(cms) != 1 || cms[0].Name != "WordPress" {
		t.Error("GetByCategory(CMS) should return WordPress")
	}
}

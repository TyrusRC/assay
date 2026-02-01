package parser

import (
	"strings"
	"testing"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/templates"
)

func TestNew(t *testing.T) {
	p := New()
	if p == nil {
		t.Fatal("New() returned nil")
	}
	if p.Strict {
		t.Error("Strict should default to false")
	}
}

func TestParseBytes_ValidTemplate(t *testing.T) {
	yaml := `
id: test-template
info:
  name: Test Template
  author: tester
  severity: high
  description: A test template
  tags: test,example
http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    matchers:
      - type: status
        status:
          - 200
`
	p := New()
	tmpl, err := p.ParseBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseBytes() error: %v", err)
	}

	if tmpl.ID != "test-template" {
		t.Errorf("ID = %q, want test-template", tmpl.ID)
	}
	if tmpl.Info.Name != "Test Template" {
		t.Errorf("Name = %q, want Test Template", tmpl.Info.Name)
	}
	if tmpl.Info.Severity != core.SeverityHigh {
		t.Errorf("Severity = %q, want high", tmpl.Info.Severity)
	}
	if len(tmpl.HTTP) != 1 {
		t.Fatalf("HTTP len = %d, want 1", len(tmpl.HTTP))
	}
	if len(tmpl.HTTP[0].Matchers) != 1 {
		t.Errorf("Matchers len = %d, want 1", len(tmpl.HTTP[0].Matchers))
	}
}

func TestParseBytes_MissingID(t *testing.T) {
	yaml := `
info:
  name: No ID Template
http:
  - path:
      - "/"
`
	p := New()
	_, err := p.ParseBytes([]byte(yaml))
	if err == nil {
		t.Error("Expected error for missing ID")
	}
}

func TestParseBytes_MissingName(t *testing.T) {
	yaml := `
id: test
info:
  author: test
http:
  - path:
      - "/"
`
	p := New()
	_, err := p.ParseBytes([]byte(yaml))
	if err == nil {
		t.Error("Expected error for missing name")
	}
}

func TestParseBytes_NoProtocolHandler(t *testing.T) {
	yaml := `
id: test
info:
  name: No Handler
`
	p := New()
	_, err := p.ParseBytes([]byte(yaml))
	if err == nil {
		t.Error("Expected error for missing protocol handler")
	}
}

func TestParseBytes_InvalidMatcher(t *testing.T) {
	yaml := `
id: test
info:
  name: Invalid Matcher
http:
  - path:
      - "/"
    matchers:
      - type: invalid
`
	p := New()
	_, err := p.ParseBytes([]byte(yaml))
	if err == nil {
		t.Error("Expected error for invalid matcher type")
	}
}

func TestParseBytes_WordMatcherNoWords(t *testing.T) {
	yaml := `
id: test
info:
  name: No Words
http:
  - path:
      - "/"
    matchers:
      - type: word
`
	p := New()
	_, err := p.ParseBytes([]byte(yaml))
	if err == nil {
		t.Error("Expected error for word matcher without words")
	}
}

func TestParse_Reader(t *testing.T) {
	yaml := `
id: reader-test
info:
  name: Reader Test
http:
  - path:
      - "/"
    matchers:
      - type: status
        status:
          - 200
`
	p := New()
	tmpl, err := p.Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if tmpl.ID != "reader-test" {
		t.Errorf("ID = %q, want reader-test", tmpl.ID)
	}
}

func TestFilterTemplatesByTags(t *testing.T) {
	tmpls := []*templates.Template{
		{ID: "t1", Info: templates.Info{Tags: "sqli,injection"}},
		{ID: "t2", Info: templates.Info{Tags: "xss,injection"}},
		{ID: "t3", Info: templates.Info{Tags: "ssrf,network"}},
		{ID: "t4", Info: templates.Info{Tags: "lfi,file"}},
	}

	tests := []struct {
		name        string
		includeTags []string
		excludeTags []string
		wantIDs     []string
	}{
		{
			name:        "Include sqli",
			includeTags: []string{"sqli"},
			wantIDs:     []string{"t1"},
		},
		{
			name:        "Include injection",
			includeTags: []string{"injection"},
			wantIDs:     []string{"t1", "t2"},
		},
		{
			name:        "Exclude injection",
			excludeTags: []string{"injection"},
			wantIDs:     []string{"t3", "t4"},
		},
		{
			name:        "Include network, exclude ssrf",
			includeTags: []string{"network"},
			excludeTags: []string{"ssrf"},
			wantIDs:     []string{},
		},
		{
			name:    "No filters",
			wantIDs: []string{"t1", "t2", "t3", "t4"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := FilterTemplatesByTags(tmpls, tt.includeTags, tt.excludeTags)
			if len(filtered) != len(tt.wantIDs) {
				t.Errorf("Got %d templates, want %d", len(filtered), len(tt.wantIDs))
				return
			}
			for i, tmpl := range filtered {
				if tmpl.ID != tt.wantIDs[i] {
					t.Errorf("Template[%d].ID = %q, want %q", i, tmpl.ID, tt.wantIDs[i])
				}
			}
		})
	}
}

func TestFilterTemplatesBySeverity(t *testing.T) {
	tmpls := []*templates.Template{
		{ID: "t1", Info: templates.Info{Severity: core.SeverityCritical}},
		{ID: "t2", Info: templates.Info{Severity: core.SeverityHigh}},
		{ID: "t3", Info: templates.Info{Severity: core.SeverityMedium}},
		{ID: "t4", Info: templates.Info{Severity: core.SeverityLow}},
		{ID: "t5", Info: templates.Info{Severity: core.SeverityInfo}},
	}

	tests := []struct {
		name       string
		severities []core.Severity
		wantIDs    []string
	}{
		{
			name:       "Critical only",
			severities: []core.Severity{core.SeverityCritical},
			wantIDs:    []string{"t1"},
		},
		{
			name:       "High and Critical",
			severities: []core.Severity{core.SeverityCritical, core.SeverityHigh},
			wantIDs:    []string{"t1", "t2"},
		},
		{
			name:    "No filter",
			wantIDs: []string{"t1", "t2", "t3", "t4", "t5"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := FilterTemplatesBySeverity(tmpls, tt.severities)
			if len(filtered) != len(tt.wantIDs) {
				t.Errorf("Got %d templates, want %d", len(filtered), len(tt.wantIDs))
			}
		})
	}
}

func TestIsYAMLFile(t *testing.T) {
	tests := []struct {
		path   string
		expect bool
	}{
		{"template.yaml", true},
		{"template.yml", true},
		{"template.YAML", true},
		{"template.json", false},
		{"template.txt", false},
		{"template", false},
	}

	for _, tt := range tests {
		if isYAMLFile(tt.path) != tt.expect {
			t.Errorf("isYAMLFile(%q) = %v, want %v", tt.path, !tt.expect, tt.expect)
		}
	}
}

func TestParseTags(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"sqli,xss,lfi", []string{"sqli", "xss", "lfi"}},
		{"sqli, xss , lfi", []string{"sqli", "xss", "lfi"}},
		{"", nil},
		{"single", []string{"single"}},
	}

	for _, tt := range tests {
		result := parseTags(tt.input)
		if len(result) != len(tt.expected) {
			t.Errorf("parseTags(%q) len = %d, want %d", tt.input, len(result), len(tt.expected))
			continue
		}
		for i, tag := range result {
			if tag != tt.expected[i] {
				t.Errorf("parseTags(%q)[%d] = %q, want %q", tt.input, i, tag, tt.expected[i])
			}
		}
	}
}

func TestContainsTag(t *testing.T) {
	tags := []string{"sqli", "xss", "injection"}

	if !containsTag(tags, "sqli") {
		t.Error("containsTag should find sqli")
	}
	if !containsTag(tags, "SQLI") {
		t.Error("containsTag should be case-insensitive")
	}
	if containsTag(tags, "lfi") {
		t.Error("containsTag should not find lfi")
	}
}

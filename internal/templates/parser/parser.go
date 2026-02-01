// Package parser provides YAML parsing for nuclei-compatible templates.
package parser

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/templates"
	"gopkg.in/yaml.v3"
)

// Parser parses nuclei template files.
type Parser struct {
	// Strict mode fails on unknown fields
	Strict bool
}

// New creates a new template parser.
func New() *Parser {
	return &Parser{
		Strict: false,
	}
}

// ParseFile parses a template from a file path.
func (p *Parser) ParseFile(path string) (*templates.Template, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open template file: %w", err)
	}
	defer file.Close()

	tmpl, err := p.Parse(file)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template %s: %w", path, err)
	}

	tmpl.Path = path
	return tmpl, nil
}

// Parse parses a template from a reader.
func (p *Parser) Parse(r io.Reader) (*templates.Template, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read template: %w", err)
	}

	return p.ParseBytes(data)
}

// ParseBytes parses a template from bytes.
func (p *Parser) ParseBytes(data []byte) (*templates.Template, error) {
	var tmpl templates.Template

	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	if p.Strict {
		decoder.KnownFields(true)
	}

	if err := decoder.Decode(&tmpl); err != nil {
		return nil, fmt.Errorf("failed to decode YAML: %w", err)
	}

	// Validate template
	if err := p.validate(&tmpl); err != nil {
		return nil, fmt.Errorf("template validation failed: %w", err)
	}

	return &tmpl, nil
}

// ParseDirectory parses all templates in a directory recursively.
func (p *Parser) ParseDirectory(dir string) ([]*templates.Template, error) {
	var tmpls []*templates.Template
	var parseErrors []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip non-YAML files
		if info.IsDir() || !isYAMLFile(path) {
			return nil
		}

		tmpl, err := p.ParseFile(path)
		if err != nil {
			parseErrors = append(parseErrors, fmt.Sprintf("%s: %v", path, err))
			return nil // Continue parsing other files
		}

		tmpls = append(tmpls, tmpl)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	if len(parseErrors) > 0 && len(tmpls) == 0 {
		return nil, fmt.Errorf("all templates failed to parse: %s", strings.Join(parseErrors, "; "))
	}

	if len(parseErrors) > 0 {
		return tmpls, fmt.Errorf("partial parse failures (%d of %d): %s",
			len(parseErrors), len(tmpls)+len(parseErrors), strings.Join(parseErrors, "; "))
	}

	return tmpls, nil
}

// validate validates a parsed template.
func (p *Parser) validate(tmpl *templates.Template) error {
	if tmpl.ID == "" {
		return fmt.Errorf("template ID is required")
	}

	if tmpl.Info.Name == "" {
		return fmt.Errorf("template name is required")
	}

	// Check that at least one protocol handler is defined
	hasHandler := len(tmpl.HTTP) > 0 ||
		len(tmpl.Network) > 0 ||
		len(tmpl.TCP) > 0 ||
		len(tmpl.DNS) > 0 ||
		len(tmpl.File) > 0 ||
		len(tmpl.Headless) > 0 ||
		len(tmpl.SSL) > 0 ||
		len(tmpl.Websocket) > 0 ||
		len(tmpl.Whois) > 0 ||
		len(tmpl.Code) > 0 ||
		len(tmpl.Javascript) > 0 ||
		len(tmpl.Workflows) > 0 ||
		tmpl.Flow != ""

	if !hasHandler {
		return fmt.Errorf("template must define at least one protocol handler")
	}

	// Validate HTTP requests
	for i, req := range tmpl.HTTP {
		if err := p.validateHTTPRequest(&req, i); err != nil {
			return err
		}
	}

	return nil
}

// validateHTTPRequest validates an HTTP request configuration.
func (p *Parser) validateHTTPRequest(req *templates.HTTPRequest, index int) error {
	// Either path or raw must be specified
	if len(req.Path) == 0 && len(req.Raw) == 0 && len(req.Fuzzing) == 0 {
		return fmt.Errorf("HTTP request %d must have path, raw, or fuzzing defined", index)
	}

	// Validate matchers
	for j, matcher := range req.Matchers {
		if err := validateMatcher(&matcher, j); err != nil {
			return fmt.Errorf("HTTP request %d: %w", index, err)
		}
	}

	return nil
}

// validateMatcher validates a matcher configuration.
func validateMatcher(m *templates.Matcher, index int) error {
	validTypes := map[string]bool{
		"word":   true,
		"regex":  true,
		"status": true,
		"size":   true,
		"binary": true,
		"dsl":    true,
		"xpath":  true,
		"time":   true,
	}

	if !validTypes[m.Type] {
		return fmt.Errorf("matcher %d has invalid type: %s", index, m.Type)
	}

	switch m.Type {
	case "word":
		if len(m.Words) == 0 {
			return fmt.Errorf("word matcher %d must have words defined", index)
		}
	case "regex":
		if len(m.Regex) == 0 {
			return fmt.Errorf("regex matcher %d must have regex patterns defined", index)
		}
	case "status":
		if len(m.Status) == 0 {
			return fmt.Errorf("status matcher %d must have status codes defined", index)
		}
	case "size":
		if len(m.Size) == 0 {
			return fmt.Errorf("size matcher %d must have sizes defined", index)
		}
	case "binary":
		if len(m.Binary) == 0 {
			return fmt.Errorf("binary matcher %d must have binary patterns defined", index)
		}
	case "dsl":
		if len(m.DSL) == 0 {
			return fmt.Errorf("dsl matcher %d must have expressions defined", index)
		}
	case "xpath":
		if len(m.XPath) == 0 {
			return fmt.Errorf("xpath matcher %d must have xpath expressions defined", index)
		}
	case "time":
		if len(m.DSL) == 0 {
			return fmt.Errorf("time matcher %d must have time expressions defined", index)
		}
	}

	return nil
}

// isYAMLFile checks if a file is a YAML file.
func isYAMLFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}

// FilterTemplatesByTags filters templates by tags.
func FilterTemplatesByTags(tmpls []*templates.Template, includeTags, excludeTags []string) []*templates.Template {
	if len(includeTags) == 0 && len(excludeTags) == 0 {
		return tmpls
	}

	var filtered []*templates.Template
	for _, tmpl := range tmpls {
		tags := parseTags(tmpl.Info.Tags)

		// Check exclusions first
		excluded := false
		for _, excludeTag := range excludeTags {
			if containsTag(tags, excludeTag) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}

		// Check inclusions
		if len(includeTags) == 0 {
			filtered = append(filtered, tmpl)
			continue
		}

		for _, includeTag := range includeTags {
			if containsTag(tags, includeTag) {
				filtered = append(filtered, tmpl)
				break
			}
		}
	}

	return filtered
}

// FilterTemplatesBySeverity filters templates by severity.
func FilterTemplatesBySeverity(tmpls []*templates.Template, severities []core.Severity) []*templates.Template {
	if len(severities) == 0 {
		return tmpls
	}

	severitySet := make(map[core.Severity]bool)
	for _, s := range severities {
		severitySet[s] = true
	}

	var filtered []*templates.Template
	for _, tmpl := range tmpls {
		if severitySet[tmpl.Info.Severity] {
			filtered = append(filtered, tmpl)
		}
	}

	return filtered
}

// parseTags parses comma-separated tags string.
func parseTags(tags string) []string {
	if tags == "" {
		return nil
	}

	parts := strings.Split(tags, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		tag := strings.TrimSpace(p)
		if tag != "" {
			result = append(result, strings.ToLower(tag))
		}
	}
	return result
}

// containsTag checks if a tag list contains a specific tag.
func containsTag(tags []string, target string) bool {
	target = strings.ToLower(target)
	for _, tag := range tags {
		if tag == target {
			return true
		}
	}
	return false
}

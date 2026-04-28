package scanner

import (
	"context"
	"strings"

	"github.com/swiss-knife-for-web-security/skws/internal/detection/techstack"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

// detectTechnologiesWithClient detects web technologies using the provided client.
func (s *InternalScanner) detectTechnologiesWithClient(ctx context.Context, targetURL string, client *http.Client) *techstack.DetectionResult {
	resp, err := client.Get(ctx, targetURL)
	if err != nil {
		return nil
	}

	return s.techDetector.Analyze(targetURL, resp.Headers, resp.Body)
}

// techAwareConfig adjusts scan configuration based on detected technologies.
// It enables/disables detectors and sets priority hints.
func (s *InternalScanner) techAwareConfig(techResult *techstack.DetectionResult) *TechHint {
	hint := &TechHint{
		Technologies: make([]string, 0),
	}

	if techResult == nil {
		return hint
	}

	for _, tech := range techResult.Technologies {
		normalized := strings.ToLower(tech.Name)
		hint.Technologies = append(hint.Technologies, normalized)
	}

	templateEngines := map[string]string{
		"jinja2":     "jinja2",
		"twig":       "twig",
		"freemarker": "freemarker",
		"django":     "django",
		"erb":        "erb",
		"smarty":     "smarty",
	}

	for _, tech := range hint.Technologies {
		switch {
		case tech == "php":
			hint.LFIWrappers = true
		case tech == "java" || tech == "spring" || tech == "tomcat":
			hint.JavaDeser = true
		case tech == "node" || tech == "express" || tech == "next":
			hint.NodeProto = true
		}

		if engine, ok := templateEngines[tech]; ok && hint.TemplateEngine == "" {
			hint.TemplateEngine = engine
		}
	}

	return hint
}

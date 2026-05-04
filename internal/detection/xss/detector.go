package xss

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	internalctx "github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/context"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/payloads/xss"
)

// Pre-compiled regexes for context analysis to avoid per-call compilation.
var (
	attrPattern    = regexp.MustCompile(`\w+\s*=\s*["'][^"']*$`)
	eventHandlerRe = regexp.MustCompile(`(?i)\bon\w+\s*=`)
	urlAttrRe      = regexp.MustCompile(`(?i)(href|src|action|data|poster|formaction)\s*=\s*["']`)
)

// Detector performs XSS vulnerability detection.
type Detector struct {
	client          *http.Client
	contextAnalyzer *internalctx.Analyzer
	verbose         bool
}

// New creates a new XSS Detector.
func New(client *http.Client) *Detector {
	return &Detector{
		client:          client,
		contextAnalyzer: internalctx.NewAnalyzer(),
	}
}

// WithVerbose enables verbose output.
func (d *Detector) WithVerbose(verbose bool) *Detector {
	d.verbose = verbose
	return d
}

// DetectOptions configures detection behavior.
type DetectOptions struct {
	// Maximum number of payloads to test
	MaxPayloads int
	// Include WAF bypass payloads
	IncludeWAFBypass bool
	// Timeout for each request
	Timeout time.Duration
	// Test all contexts or just detected context
	TestAllContexts bool
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		MaxPayloads:      50,
		IncludeWAFBypass: true,
		Timeout:          10 * time.Second,
		TestAllContexts:  false,
	}
}

// DetectionResult contains XSS detection results.
type DetectionResult struct {
	Vulnerable      bool
	Findings        []*core.Finding
	TestedPayloads  int
	DetectedContext xss.Context
}

// Detect tests a parameter for XSS vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	// First, analyze the reflection context with a probe value
	probeValue := "xssprobe" + fmt.Sprintf("%d", time.Now().UnixNano()%10000)
	resp, err := d.client.SendPayload(ctx, target, param, probeValue, method)
	if err != nil {
		return result, fmt.Errorf("failed to send probe: %w", err)
	}

	// Find where the probe value appears
	reflections := d.findReflections(resp.Body, probeValue)
	if len(reflections) == 0 {
		// No reflection found, try DOM-based detection
		result.DetectedContext = xss.HTMLContext
	} else {
		// Analyze each reflection context
		for _, r := range reflections {
			contextType := d.analyzeReflectionContext(resp.Body, r)
			result.DetectedContext = contextType
			break // Use first reflection context
		}
	}

	// Get payloads based on context
	var payloads []xss.Payload
	if opts.TestAllContexts {
		payloads = xss.GetAllPayloads()
	} else {
		payloads = xss.GetPayloads(result.DetectedContext)
		// Add polyglots for extra coverage
		payloads = append(payloads, xss.GetPolyglotPayloads()...)
	}

	// Add WAF bypass payloads if requested
	if opts.IncludeWAFBypass {
		payloads = append(payloads, xss.GetWAFBypassPayloads()...)
	}

	// Deduplicate payloads
	payloads = d.deduplicatePayloads(payloads)

	// Limit number of payloads
	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	// Test each payload
	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		result.TestedPayloads++

		// Send payload
		testResp, err := d.client.SendPayload(ctx, target, param, payload.Value, method)
		if err != nil {
			continue
		}

		// Check if payload is reflected
		if d.isPayloadReflected(testResp.Body, payload) {
			finding := d.createFinding(target, param, payload, testResp)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true

			// For efficiency, stop after finding first vulnerability (unless testing all)
			if !opts.TestAllContexts {
				break
			}
		}
	}

	return result, nil
}

// findReflections finds all positions where the probe appears in the response.
// An empty probe matches at every byte position; we return nil instead of
// looping forever, since "no probe" carries no detection signal.
func (d *Detector) findReflections(body, probe string) []int {
	if probe == "" {
		return nil
	}
	var positions []int
	start := 0
	for {
		idx := strings.Index(body[start:], probe)
		if idx == -1 {
			break
		}
		positions = append(positions, start+idx)
		start = start + idx + len(probe)
	}
	return positions
}

// analyzeReflectionContext determines the context where input is reflected.
func (d *Detector) analyzeReflectionContext(body string, position int) xss.Context {
	// Get surrounding context (200 chars before and after)
	start := position - 200
	if start < 0 {
		start = 0
	}
	end := position + 200
	if end > len(body) {
		end = len(body)
	}
	context := body[start:end]

	// Check if inside a script tag
	if d.isInsideTag(context, "script") {
		return xss.JavaScriptContext
	}

	// Check if inside a style tag
	if d.isInsideTag(context, "style") {
		return xss.CSSContext
	}

	// Check if inside an attribute
	if d.isInsideAttribute(context, position-start) {
		// Check if it's an event handler
		if d.isEventHandler(context) {
			return xss.JavaScriptContext
		}
		// Check if it's a URL attribute
		if d.isURLAttribute(context) {
			return xss.URLContext
		}
		return xss.AttributeContext
	}

	// Check for template syntax
	if d.hasTemplateSyntax(context) {
		return xss.TemplateContext
	}

	// Default to HTML context
	return xss.HTMLContext
}

// Pre-compiled regexes for tag detection.
var (
	scriptOpenRe  = regexp.MustCompile(`(?i)<script[^>]*>`)
	scriptCloseRe = regexp.MustCompile(`(?i)</script>`)
	styleOpenRe   = regexp.MustCompile(`(?i)<style[^>]*>`)
	styleCloseRe  = regexp.MustCompile(`(?i)</style>`)
)

func (d *Detector) isInsideTag(ctx, tag string) bool {
	var openTag *regexp.Regexp
	switch tag {
	case "script":
		openTag = scriptOpenRe
	case "style":
		openTag = styleOpenRe
	default:
		openTag = regexp.MustCompile(`(?i)<` + tag + `[^>]*>`)
	}
	// `ctx` is a 400-char window around the reflection point; we're
	// asking "is there any chance the reflection lies inside a <tag>...".
	// The presence of an opening tag in that window is the right signal:
	// a matched pair means we entered the scope; an unclosed open later
	// in the window means we're still in it. A bare closing tag (without
	// any open) cannot place the reflection inside the tag.
	return openTag.MatchString(ctx)
}

// isInsideAttribute checks if position is inside an HTML attribute.
func (d *Detector) isInsideAttribute(ctx string, relativePos int) bool {
	beforePos := ctx[:relativePos]
	return attrPattern.MatchString(beforePos)
}

// isEventHandler checks if inside an event handler attribute.
func (d *Detector) isEventHandler(ctx string) bool {
	return eventHandlerRe.MatchString(ctx)
}

// isURLAttribute checks if inside a URL attribute (href, src, action, etc.).
func (d *Detector) isURLAttribute(ctx string) bool {
	return urlAttrRe.MatchString(ctx)
}

// hasTemplateSyntax checks for common template syntax.
func (d *Detector) hasTemplateSyntax(context string) bool {
	templates := []string{
		"{{", "}}", // Jinja2, Angular, Vue
		"<%=", "%>", // ERB
		"${",       // Freemarker, JS template
		"{%", "%}", // Django, Twig
	}
	for _, t := range templates {
		if strings.Contains(context, t) {
			return true
		}
	}
	return false
}

// isPayloadReflected checks if the XSS payload is reflected in a dangerous way.
func (d *Detector) isPayloadReflected(body string, payload xss.Payload) bool {
	if payload.Value == "" {
		return false
	}

	// Check for exact reflection of the full payload
	if strings.Contains(body, payload.Value) {
		return true
	}

	// Check for HTML-decoded reflection
	decoded := d.htmlDecode(payload.Value)
	if decoded != payload.Value && strings.Contains(body, decoded) {
		return true
	}

	return false
}

// htmlDecode performs basic HTML entity decoding.
func (d *Detector) htmlDecode(s string) string {
	replacer := strings.NewReplacer(
		"&lt;", "<",
		"&gt;", ">",
		"&quot;", "\"",
		"&#39;", "'",
		"&amp;", "&",
	)
	return replacer.Replace(s)
}

// deduplicatePayloads removes duplicate payloads.
func (d *Detector) deduplicatePayloads(payloads []xss.Payload) []xss.Payload {
	seen := make(map[string]bool)
	var unique []xss.Payload
	for _, p := range payloads {
		if !seen[p.Value] {
			seen[p.Value] = true
			unique = append(unique, p)
		}
	}
	return unique
}

// createFinding creates a Finding from a successful XSS test.
func (d *Detector) createFinding(target, param string, payload xss.Payload, resp *http.Response) *core.Finding {
	severity := core.SeverityHigh
	if payload.Type == xss.TypeStored {
		severity = core.SeverityCritical
	}

	finding := core.NewFinding("Cross-Site Scripting (XSS)", severity)
	finding.URL = target
	finding.Parameter = param
	finding.Description = fmt.Sprintf("%s XSS vulnerability in '%s' parameter (%s context)",
		payload.Type, param, payload.Context)
	finding.Evidence = payload.Value
	finding.Tool = "xss-detector"

	// Add remediation
	finding.Remediation = "Implement proper output encoding based on context. " +
		"Use Content-Security-Policy headers. " +
		"Validate and sanitize all user input."

	// OWASP mappings
	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-02"}, // XSS testing
		[]string{"A03:2025"},     // Injection
		[]string{"CWE-79"},       // XSS
	)

	return finding
}

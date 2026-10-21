package xxe

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
	"github.com/TyrusRC/assay/internal/payloads/xxe"
)

// Detector performs XXE vulnerability detection.
type Detector struct {
	client          *http.Client
	verbose         bool
	contentPatterns []*regexp.Regexp
	errorPatterns   []*regexp.Regexp
}

// New creates a new XXE Detector.
func New(client *http.Client) *Detector {
	d := &Detector{
		client: client,
	}
	d.initPatterns()
	return d
}

// WithVerbose enables verbose output.
func (d *Detector) WithVerbose(verbose bool) *Detector {
	d.verbose = verbose
	return d
}

// initPatterns initializes patterns for detecting XXE success.
func (d *Detector) initPatterns() {
	// Patterns indicating successful file read
	d.contentPatterns = []*regexp.Regexp{
		// /etc/passwd patterns
		regexp.MustCompile(`root:x:0:0:`),
		regexp.MustCompile(`root:[^:]*:0:0:`),
		regexp.MustCompile(`daemon:x:\d+:\d+:`),
		regexp.MustCompile(`nobody:x:\d+:\d+:`),

		// /etc/hosts patterns
		regexp.MustCompile(`127\.0\.0\.1\s+localhost`),
		regexp.MustCompile(`::1\s+localhost`),

		// Windows patterns
		regexp.MustCompile(`(?i)\[fonts\]`),
		regexp.MustCompile(`(?i)\[extensions\]`),
		regexp.MustCompile(`(?i)\[mci extensions\]`),

		// AWS metadata patterns
		regexp.MustCompile(`ami-[a-f0-9]+`),
		regexp.MustCompile(`(?i)instance-id`),

		// Generic file patterns
		regexp.MustCompile(`PATH=.*:`),
		regexp.MustCompile(`HOME=/`),
		regexp.MustCompile(`-----BEGIN.*KEY-----`),
	}

	// Patterns indicating XXE error messages (even without data)
	d.errorPatterns = []*regexp.Regexp{
		// XML parsing errors that indicate entity processing
		regexp.MustCompile(`(?i)failed to load external entity`),
		regexp.MustCompile(`(?i)error loading external entity`),
		regexp.MustCompile(`(?i)external entity`),
		regexp.MustCompile(`(?i)SYSTEM.*entity`),
		regexp.MustCompile(`(?i)DTD.*not.*allowed`),
		regexp.MustCompile(`(?i)DOCTYPE.*disallowed`),
		regexp.MustCompile(`(?i)entity.*expansion`),
		regexp.MustCompile(`(?i)recursive entity`),

		// Network-related errors (indicates SSRF capability)
		regexp.MustCompile(`(?i)connection.*refused`),
		regexp.MustCompile(`(?i)name.*resolution.*failed`),
		regexp.MustCompile(`(?i)could.*not.*resolve.*host`),
		regexp.MustCompile(`(?i)network.*unreachable`),

		// File access errors (indicates file read capability)
		regexp.MustCompile(`(?i)permission.*denied`),
		regexp.MustCompile(`(?i)no.*such.*file`),
		regexp.MustCompile(`(?i)failed.*to.*open`),
		regexp.MustCompile(`(?i)file.*not.*found`),
	}
}

// DetectOptions configures detection behavior.
type DetectOptions struct {
	MaxPayloads  int
	Timeout      time.Duration
	TestTypes    []xxe.XXEType
	TargetParser xxe.Parser
	ContentType  string // application/xml, text/xml, etc.
	CallbackURL  string // OOB callback URL for blind XXE (e.g. interactsh)
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		MaxPayloads:  20,
		Timeout:      10 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic, xxe.TypeErrorBased},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}
}

// DetectionResult contains XXE detection results.
type DetectionResult struct {
	Vulnerable      bool
	Findings        []*core.Finding
	TestedPayloads  int
	DetectedType    xxe.XXEType
	DetectedTarget  xxe.TargetType
	ExfiltratedData string
}

// Detect tests for XXE vulnerabilities.
// Unlike other detectors, XXE testing typically requires the full request body to be XML.
func (d *Detector) Detect(ctx context.Context, target, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	// Collect payloads based on test types
	var payloads []xxe.Payload
	for _, testType := range opts.TestTypes {
		payloads = append(payloads, xxe.GetPayloads(testType)...)
	}

	// Filter by target parser if specified
	if opts.TargetParser != xxe.ParserGeneric {
		var filtered []xxe.Payload
		for _, p := range payloads {
			if p.Parser == xxe.ParserGeneric || p.Parser == opts.TargetParser {
				filtered = append(filtered, p)
			}
		}
		payloads = filtered
	}

	// Limit number of payloads
	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	// Get baseline response with valid XML
	baselineXML := `<?xml version="1.0"?><test>baseline</test>`
	baselineResp, err := d.sendXMLPayload(ctx, target, method, baselineXML, opts.ContentType)
	if err != nil {
		return result, fmt.Errorf("failed to get baseline: %w", err)
	}

	// Test each payload
	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		result.TestedPayloads++

		resp, err := d.sendXMLPayload(ctx, target, method, payload.Value, opts.ContentType)
		if err != nil {
			continue
		}

		// Check for XXE indicators
		success, extractedData := d.checkXXESuccess(resp, baselineResp, payload)
		if success {
			finding := d.createFinding(target, payload, resp, extractedData)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			result.DetectedType = payload.Type
			result.DetectedTarget = payload.Target
			result.ExfiltratedData = extractedData

			// Continue to find more vulnerabilities (different types)
			if len(result.Findings) >= 2 {
				return result, nil
			}
		}
	}

	return result, nil
}

// DetectInParameter tests a parameter for XXE when XML is passed in a parameter.
func (d *Detector) DetectInParameter(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	// Get payloads
	var payloads []xxe.Payload
	for _, testType := range opts.TestTypes {
		payloads = append(payloads, xxe.GetPayloads(testType)...)
	}

	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	// Get baseline
	baselineXML := `<?xml version="1.0"?><test>baseline</test>`
	baselineResp, err := d.client.SendPayload(ctx, target, param, baselineXML, method)
	if err != nil {
		return result, fmt.Errorf("failed to get baseline: %w", err)
	}

	// Test payloads
	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		result.TestedPayloads++

		resp, err := d.client.SendPayload(ctx, target, param, payload.Value, method)
		if err != nil {
			continue
		}

		success, extractedData := d.checkXXESuccess(resp, baselineResp, payload)
		if success {
			finding := d.createFindingWithParam(target, param, payload, resp, extractedData)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			result.DetectedType = payload.Type
			result.DetectedTarget = payload.Target
			result.ExfiltratedData = extractedData

			return result, nil
		}
	}

	return result, nil
}

// sendXMLPayload sends XML content as the request body.
func (d *Detector) sendXMLPayload(ctx context.Context, target, method, xmlContent, contentType string) (*http.Response, error) {
	return d.client.SendRawBody(ctx, target, method, xmlContent, contentType)
}

// checkXXESuccess checks if the response indicates successful XXE exploitation.
func (d *Detector) checkXXESuccess(resp, baseline *http.Response, payload xxe.Payload) (bool, string) {
	if resp == nil {
		return false, ""
	}

	body := resp.Body

	// Check for file content patterns
	for _, pattern := range d.contentPatterns {
		if pattern.MatchString(body) {
			// Make sure it's not in baseline
			if baseline != nil && pattern.MatchString(baseline.Body) {
				continue
			}
			// Extract the matched content
			matches := pattern.FindStringSubmatch(body)
			if len(matches) > 0 {
				return true, matches[0]
			}
			return true, ""
		}
	}

	// Check for error messages that indicate XXE processing
	for _, pattern := range d.errorPatterns {
		if pattern.MatchString(body) {
			if baseline != nil && pattern.MatchString(baseline.Body) {
				continue
			}
			// Error-based XXE confirmed
			return true, ""
		}
	}

	// Check for significant response differences
	if baseline != nil {
		// Response much different from baseline might indicate XXE
		if d.significantlyDifferent(body, baseline.Body) {
			// Additional check: look for file-like content absent in baseline
			if d.hasFileContent(body, baseline.Body) {
				return true, ""
			}
		}
	}

	return false, ""
}

// significantlyDifferent checks if two responses are significantly different.
func (d *Detector) significantlyDifferent(body1, body2 string) bool {
	// Length difference
	if len(body1) > len(body2)*2 || len(body2) > len(body1)*2 {
		return true
	}

	// Simple similarity check
	if len(body1) < 100 || len(body2) < 100 {
		return body1 != body2
	}

	// Compare substrings
	sampleSize := 100
	if len(body1) >= sampleSize && len(body2) >= sampleSize {
		if body1[:sampleSize] != body2[:sampleSize] {
			return true
		}
	}

	return false
}

// hasFileContent checks if the response contains file-like content that
// is NOT already present in the baseline response.
func (d *Detector) hasFileContent(body, baselineBody string) bool {
	fileIndicators := []string{
		"root:", "daemon:", "nobody:",
		"127.0.0.1", "localhost",
		"[fonts]", "[extensions]",
		"PATH=", "HOME=", "USER=",
		"-----BEGIN",
	}

	for _, indicator := range fileIndicators {
		if strings.Contains(body, indicator) && !strings.Contains(baselineBody, indicator) {
			return true
		}
	}

	return false
}

// doctypeNameRe matches the DOCTYPE declaration name for rewriting.
var doctypeNameRe = regexp.MustCompile(`<!DOCTYPE\s+\w+`)

// entityRefRe extracts &entityname; references from the payload body.
var entityRefRe = regexp.MustCompile(`&\w+;`)

// DetectInXMLBody tests for XXE when the endpoint expects a full XML body.
// Unlike DetectInParameter (which injects into a single field), this replaces
// the entire body with XXE payloads that use the parameter name as the
// entity-expansion element. This is the correct approach for endpoints
// discovered via OpenAPI with content-type application/xml.
func (d *Detector) DetectInXMLBody(ctx context.Context, target, paramName, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	var payloads []xxe.Payload
	for _, testType := range opts.TestTypes {
		payloads = append(payloads, xxe.GetPayloads(testType)...)
	}
	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	ct := opts.ContentType
	if ct == "" {
		ct = "application/xml"
	}

	baselineXML := fmt.Sprintf("<?xml version=\"1.0\"?><%s>baseline</%s>", paramName, paramName)
	baselineResp, err := d.client.SendRawBody(ctx, target, method, baselineXML, ct)
	if err != nil {
		return result, fmt.Errorf("failed to get baseline: %w", err)
	}

	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}
		result.TestedPayloads++

		xmlBody := buildXXEBody(payload.Value, paramName)

		resp, err := d.client.SendRawBody(ctx, target, method, xmlBody, ct)
		if err != nil {
			continue
		}

		success, extractedData := d.checkXXESuccess(resp, baselineResp, payload)
		if success {
			finding := d.createFindingWithParam(target, paramName, payload, resp, extractedData)
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			result.DetectedType = payload.Type
			result.DetectedTarget = payload.Target
			result.ExfiltratedData = extractedData
			return result, nil
		}
	}

	// Blind/OOB XXE: when a callback URL is available, send payloads that
	// trigger an outbound DNS/HTTP request to prove entity resolution.
	if opts.CallbackURL != "" {
		blindPayloads := xxe.GetPayloads(xxe.TypeBlind)
		for _, bp := range blindPayloads {
			select {
			case <-ctx.Done():
				return result, ctx.Err()
			default:
			}
			result.TestedPayloads++
			injected := strings.ReplaceAll(bp.Value, "ATTACKER_SERVER", opts.CallbackURL)
			xmlBody := buildXXEBody(injected, paramName)
			d.client.SendRawBody(ctx, target, method, xmlBody, ct)
		}
	}

	return result, nil
}

// buildXXEBody rewrites a raw XXE payload to use paramName as the root
// element and DOCTYPE name. The stock payloads all use <foo>; this swaps
// that for the real element the endpoint expects.
func buildXXEBody(rawPayload, paramName string) string {
	docStart := strings.Index(rawPayload, "<!DOCTYPE")
	if docStart < 0 {
		docStart = strings.Index(rawPayload, "<!doctype")
	}
	if docStart < 0 {
		return fmt.Sprintf("<?xml version=\"1.0\"?><%s>%s</%s>", paramName, rawPayload, paramName)
	}

	docEnd := strings.Index(rawPayload[docStart:], "]>")
	if docEnd < 0 {
		return rawPayload
	}
	docEnd += docStart + 2

	doctype := rawPayload[docStart:docEnd]
	doctypeFixed := doctypeNameRe.ReplaceAllString(doctype, "<!DOCTYPE "+paramName)

	bodyPart := rawPayload[docEnd:]
	entityRefs := entityRefRe.FindAllString(bodyPart, -1)
	entityContent := "&xxe;"
	if len(entityRefs) > 0 {
		entityContent = entityRefs[0]
	}

	return fmt.Sprintf("<?xml version=\"1.0\"?>%s<%s>%s</%s>", doctypeFixed, paramName, entityContent, paramName)
}

// createFinding creates a Finding from a successful XXE test.
func (d *Detector) createFinding(target string, payload xxe.Payload, resp *http.Response, extractedData string) *core.Finding {
	severity := core.SeverityHigh
	if payload.Target == xxe.TargetRCE {
		severity = core.SeverityCritical
	}

	finding := core.NewFinding("XML External Entity (XXE) Injection", severity)
	finding.URL = target
	finding.Description = fmt.Sprintf("XXE vulnerability detected (Type: %s, Target: %s, Parser: %s)",
		payload.Type, payload.Target, payload.Parser)

	finding.Evidence = fmt.Sprintf("Payload type: %s\nDescription: %s", payload.Type, payload.Description)
	finding.Tool = "xxe-detector"

	if extractedData != "" {
		finding.Evidence += fmt.Sprintf("\nExtracted data: %s", extractedData)
	}

	if resp != nil && len(resp.Body) > 0 {
		body := resp.Body
		if len(body) > 500 {
			body = body[:500] + "..."
		}
		finding.Evidence += fmt.Sprintf("\nResponse snippet: %s", body)
	}

	finding.Remediation = "Disable external entity processing in XML parsers. " +
		"Use defusedxml or similar libraries. " +
		"For Java, disable DOCTYPE declarations. " +
		"For PHP, set libxml_disable_entity_loader(true). " +
		"Validate and sanitize XML input."

	// OWASP mappings
	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-07"}, // XXE testing
		[]string{"A02:2025"},     // Security Misconfiguration (XXE was A4 in 2017)
		[]string{"CWE-611"},      // XXE
	)

	return finding
}

// createFindingWithParam creates a Finding for parameter-based XXE.
func (d *Detector) createFindingWithParam(target, param string, payload xxe.Payload, resp *http.Response, extractedData string) *core.Finding {
	finding := d.createFinding(target, payload, resp, extractedData)
	finding.Parameter = param
	finding.Description = fmt.Sprintf("XXE vulnerability in '%s' parameter (Type: %s, Target: %s)",
		param, payload.Type, payload.Target)
	return finding
}

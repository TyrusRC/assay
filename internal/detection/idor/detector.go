// Package idor provides Insecure Direct Object Reference (IDOR) and
// Broken Object Level Authorization (BOLA) vulnerability detection.
// It tests for unauthorized access to resources by manipulating object identifiers.
//
// OWASP Mappings:
//   - WSTG-ATHZ-04: Testing for Insecure Direct Object References
//   - A01:2021: Broken Access Control
//   - API1:2023: Broken Object Level Authorization
//   - CWE-639: Authorization Bypass Through User-Controlled Key
package idor

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

// Detector performs IDOR/BOLA vulnerability detection.
type Detector struct {
	client            *http.Client
	verbose           bool
	sensitivePatterns []*regexp.Regexp
	idPatterns        map[IDType]*regexp.Regexp
	idParameterNames  []string
	commonNumericIDs  []string

	// Pre-compiled patterns for hot-path methods
	base64Pattern *regexp.Regexp
	numPattern    *regexp.Regexp
	numSuffix     *regexp.Regexp
}

// New creates a new IDOR Detector.
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

// initPatterns initializes detection patterns.
func (d *Detector) initPatterns() {
	// Sensitive data patterns for detecting PII and confidential information
	d.sensitivePatterns = []*regexp.Regexp{
		// SSN patterns
		regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		// Credit card patterns (basic)
		regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`),
		// Email patterns
		regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`),
		// Phone number patterns
		regexp.MustCompile(`\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`),
		// Password hash patterns (bcrypt, argon2, etc.)
		regexp.MustCompile(`\$2[ayb]\$\d+\$[A-Za-z0-9./]{53}`),
		regexp.MustCompile(`\$argon2[id]+\$`),
		// API key patterns
		regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*["']?[A-Za-z0-9_-]{16,}["']?`),
		regexp.MustCompile(`(?i)sk-[a-zA-Z0-9-]{10,}`),
		regexp.MustCompile(`(?i)pk_[a-zA-Z0-9]{10,}`),
		// Address patterns (basic)
		regexp.MustCompile(`\b\d+\s+[A-Za-z]+\s+(?:St|Street|Ave|Avenue|Blvd|Boulevard|Rd|Road|Dr|Drive|Ln|Lane|Ct|Court)\b`),
		// Date of birth patterns
		regexp.MustCompile(`\b(?:dob|date[_-]?of[_-]?birth|birth[_-]?date)\s*[:=]\s*["']?\d{1,4}[-/]\d{1,2}[-/]\d{1,4}["']?`),
	}

	// ID type detection patterns
	d.idPatterns = map[IDType]*regexp.Regexp{
		IDTypeNumeric:      regexp.MustCompile(`^\d+$`),
		IDTypeUUID:         regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`),
		IDTypeHex:          regexp.MustCompile(`^[0-9a-fA-F]{12,}$`),
		IDTypeAlphanumeric: regexp.MustCompile(`^[A-Za-z0-9_-]+$`),
	}

	// Common parameter names that might contain object references
	d.idParameterNames = []string{
		"id", "user_id", "userId", "user", "uid",
		"account_id", "accountId", "account",
		"order_id", "orderId", "order",
		"doc_id", "docId", "document_id", "documentId",
		"file_id", "fileId", "file",
		"item_id", "itemId", "item",
		"product_id", "productId", "product",
		"customer_id", "customerId", "customer",
		"profile_id", "profileId", "profile",
		"record_id", "recordId", "record",
		"ref", "reference", "token",
	}

	// Common numeric IDs to test
	d.commonNumericIDs = []string{"0", "1", "2", "100", "1000", "admin", "test"}

	// Pre-compile patterns used in hot-path methods
	d.base64Pattern = regexp.MustCompile(`^[A-Za-z0-9+/]+=*$`)
	d.numPattern = regexp.MustCompile(`(\d+)`)
	d.numSuffix = regexp.MustCompile(`^(.*)(\d+)$`)
}

// DetectOptions configures detection behavior.
type DetectOptions struct {
	MaxRequests int
	Timeout     time.Duration
	IDTypes     []IDType
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		MaxRequests: 20,
		Timeout:     10 * time.Second,
		IDTypes:     []IDType{IDTypeNumeric, IDTypeUUID, IDTypeBase64, IDTypeHex},
	}
}

// DetectionResult contains IDOR detection results.
type DetectionResult struct {
	Vulnerable    bool
	Findings      []*core.Finding
	TestedIDs     int
	VulnerableIDs []string
	Evidence      []*IDOREvidence
}

// Detect tests a URL for IDOR vulnerabilities by manipulating IDs in query parameters and path.
func (d *Detector) Detect(ctx context.Context, targetURL string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
		Evidence: make([]*IDOREvidence, 0),
	}

	// Check context cancellation
	select {
	case <-ctx.Done():
		return result, ctx.Err()
	default:
	}

	// Parse the URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return result, fmt.Errorf("invalid URL: %w", err)
	}

	// Extract ID parameters from URL
	idParams := d.extractIDParameters(targetURL, "", "")

	if len(idParams) == 0 {
		return result, nil
	}

	// Get baseline response
	baselineResp, err := d.client.Get(ctx, targetURL)
	if err != nil {
		return result, fmt.Errorf("failed to get baseline: %w", err)
	}

	// Test each ID parameter
	for _, param := range idParams {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		// Generate manipulated IDs
		manipulatedIDs := d.generateManipulatedIDs(param.Value, param.Type)

		// Test each manipulated ID
		for _, testID := range manipulatedIDs {
			if result.TestedIDs >= opts.MaxRequests {
				break
			}

			select {
			case <-ctx.Done():
				return result, ctx.Err()
			default:
			}

			result.TestedIDs++

			// Build test URL with manipulated ID
			testURL := d.buildTestURL(parsedURL, param, testID)

			// Send request with manipulated ID
			testResp, err := d.client.Get(ctx, testURL)
			if err != nil {
				continue
			}

			// Analyze response for IDOR
			evidence := d.analyzeForIDOR(baselineResp, testResp, param.Value, testID)
			if evidence != nil {
				result.Evidence = append(result.Evidence, evidence)

				if d.isIDORVulnerable(evidence) {
					result.Vulnerable = true
					result.VulnerableIDs = append(result.VulnerableIDs, testID)

					finding := d.createFinding(targetURL, param, evidence, testResp)
					result.Findings = append(result.Findings, finding)

					// Limit findings per parameter
					if len(result.Findings) >= 3 {
						return result, nil
					}
				}
			}
		}
	}

	return result, nil
}

// DetectInBody tests for IDOR vulnerabilities in request body parameters.
func (d *Detector) DetectInBody(ctx context.Context, targetURL, method, body, contentType string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
		Evidence: make([]*IDOREvidence, 0),
	}

	// Check context cancellation
	select {
	case <-ctx.Done():
		return result, ctx.Err()
	default:
	}

	// Extract ID parameters from body
	idParams := d.extractIDParameters(targetURL, body, contentType)

	if len(idParams) == 0 {
		return result, nil
	}

	// Get baseline response
	baselineResp, err := d.client.SendRawBody(ctx, targetURL, method, body, contentType)
	if err != nil {
		return result, fmt.Errorf("failed to get baseline: %w", err)
	}

	// Test each ID parameter in body
	for _, param := range idParams {
		if param.Location != LocationBody {
			continue
		}

		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		// Generate manipulated IDs
		manipulatedIDs := d.generateManipulatedIDs(param.Value, param.Type)

		// Test each manipulated ID
		for _, testID := range manipulatedIDs {
			if result.TestedIDs >= opts.MaxRequests {
				break
			}

			select {
			case <-ctx.Done():
				return result, ctx.Err()
			default:
			}

			result.TestedIDs++

			// Build test body with manipulated ID
			testBody := d.buildTestBody(body, contentType, param, testID)

			// Send request with manipulated ID
			testResp, err := d.client.SendRawBody(ctx, targetURL, method, testBody, contentType)
			if err != nil {
				continue
			}

			// Analyze response for IDOR
			evidence := d.analyzeForIDOR(baselineResp, testResp, param.Value, testID)
			if evidence != nil {
				result.Evidence = append(result.Evidence, evidence)

				if d.isIDORVulnerable(evidence) {
					result.Vulnerable = true
					result.VulnerableIDs = append(result.VulnerableIDs, testID)

					finding := d.createFinding(targetURL, param, evidence, testResp)
					result.Findings = append(result.Findings, finding)

					if len(result.Findings) >= 3 {
						return result, nil
					}
				}
			}
		}
	}

	return result, nil
}

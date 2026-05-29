// Package nosql provides NoSQL injection vulnerability detection.
// It supports detection for MongoDB, CouchDB, Elasticsearch, and Redis
// using operator injection, JavaScript injection, and response-based techniques.
//
// The file layout splits responsibilities:
//
//	detector.go       — types, constructor, top-level Detect loop
//	errorpatterns.go  — per-database regex tables (initErrorPatterns)
//	analysis.go       — AnalyzeResponse, DetectDBType, JSON-structure diff
//	findings.go       — createFinding, deduplicatePayloads
package nosql

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
	"github.com/TyrusRC/assay/internal/payloads/nosql"
)

// Detector performs NoSQL Injection vulnerability detection.
type Detector struct {
	client        *http.Client
	verbose       bool
	errorPatterns map[nosql.DBType][]*regexp.Regexp
}

// New creates a new NoSQL Injection Detector.
func New(client *http.Client) *Detector {
	d := &Detector{
		client:        client,
		errorPatterns: make(map[nosql.DBType][]*regexp.Regexp),
	}
	d.initErrorPatterns()
	return d
}

// WithVerbose enables verbose output.
func (d *Detector) WithVerbose(verbose bool) *Detector {
	d.verbose = verbose
	return d
}

// Name returns the detector name.
func (d *Detector) Name() string {
	return "nosqli"
}

// Description returns the detector description.
func (d *Detector) Description() string {
	return "NoSQL Injection vulnerability detector using operator injection, JavaScript injection, and response-based techniques"
}

// DetectOptions configures detection behavior.
type DetectOptions struct {
	MaxPayloads      int
	IncludeWAFBypass bool
	Timeout          time.Duration
	DBType           nosql.DBType
	EnableTimeBased  bool
	TimeBasedDelay   time.Duration
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		MaxPayloads:      50,
		IncludeWAFBypass: true,
		Timeout:          10 * time.Second,
		DBType:           nosql.Generic,
		EnableTimeBased:  true,
		TimeBasedDelay:   5 * time.Second,
	}
}

// DetectionResult contains NoSQL injection detection results.
type DetectionResult struct {
	Vulnerable     bool
	Findings       []*core.Finding
	TestedPayloads int
	DetectedDBType nosql.DBType
}

// AnalysisResult contains the result of response analysis.
type AnalysisResult struct {
	IsVulnerable  bool
	DetectionType string
	Confidence    float64
	Evidence      string
	DatabaseType  nosql.DBType
}

// Detect tests a parameter for NoSQL Injection vulnerabilities.
func (d *Detector) Detect(ctx context.Context, target, param, method string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:       make([]*core.Finding, 0),
		DetectedDBType: opts.DBType,
	}

	// Handle empty parameter gracefully.
	if param == "" {
		return result, nil
	}

	// Get payloads based on database type.
	payloads := nosql.GetPayloads(opts.DBType)
	if opts.IncludeWAFBypass {
		payloads = append(payloads, nosql.GetWAFBypassPayloads(opts.DBType)...)
	}
	// Add generic payloads for broader coverage.
	if opts.DBType != nosql.Generic {
		payloads = append(payloads, nosql.GetPayloads(nosql.Generic)...)
	}
	payloads = d.deduplicatePayloads(payloads)
	if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
		payloads = payloads[:opts.MaxPayloads]
	}

	// Baseline.
	baselineResp, err := d.client.SendPayload(ctx, target, param, "baseline_test_value", method)
	if err != nil {
		return result, fmt.Errorf("failed to get baseline: %w", err)
	}
	baselineTime := baselineResp.Duration
	baselineBody := baselineResp.Body

	// Test error-based and response-based payloads first (faster).
	for _, payload := range payloads {
		if payload.Technique == nosql.TechTimeBased {
			continue
		}
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

		// Error-based detection. Gate on baseline-diff: if the baseline
		// already contains the same NoSQL error string (e.g. docs page
		// shipping a "Query parsing failed" example), the pattern is
		// not evidence of injection.
		if analysis := d.AnalyzeResponse(resp.Body); analysis.IsVulnerable {
			if base := d.AnalyzeResponse(baselineBody); !base.IsVulnerable {
				finding := d.createFinding(target, param, payload, resp, analysis.DetectionType)
				finding.Evidence = analysis.Evidence
				result.Findings = append(result.Findings, finding)
				result.Vulnerable = true
				result.DetectedDBType = analysis.DatabaseType
				return result, nil
			}
		}

		// Response-based detection (JSON structure changes).
		if d.HasJSONStructureChange(baselineBody, resp.Body) {
			finding := d.createFinding(target, param, payload, resp, "response-based")
			result.Findings = append(result.Findings, finding)
			result.Vulnerable = true
			return result, nil
		}
	}

	// Time-based payloads (slower; gated by EnableTimeBased).
	if opts.EnableTimeBased {
		timePayloads := nosql.GetByTechnique(opts.DBType, nosql.TechTimeBased)
		for _, payload := range timePayloads {
			select {
			case <-ctx.Done():
				return result, ctx.Err()
			default:
			}
			result.TestedPayloads++

			start := time.Now()
			_, err := d.client.SendPayload(ctx, target, param, payload.Value, method)
			elapsed := time.Since(start)
			if err != nil {
				continue
			}

			expectedDelay := opts.TimeBasedDelay
			tolerance := time.Second * 2
			if elapsed > baselineTime+expectedDelay-tolerance && elapsed < baselineTime+expectedDelay+tolerance*2 {
				finding := d.createFinding(target, param, payload, nil, "time-based")
				finding.Evidence = fmt.Sprintf("Response delayed by %v (baseline: %v, expected delay: %v)",
					elapsed, baselineTime, expectedDelay)
				result.Findings = append(result.Findings, finding)
				result.Vulnerable = true
				result.DetectedDBType = payload.DBType
				return result, nil
			}
		}
	}

	return result, nil
}

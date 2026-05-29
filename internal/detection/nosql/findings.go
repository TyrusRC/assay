package nosql

import (
	"fmt"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
	"github.com/TyrusRC/assay/internal/payloads/nosql"
)

// deduplicatePayloads removes payloads with identical Value strings.
// Kept on the detector so a future hook could deduplicate across DB
// types if the payload bank starts repeating values.
func (d *Detector) deduplicatePayloads(payloads []nosql.Payload) []nosql.Payload {
	seen := make(map[string]bool)
	var unique []nosql.Payload
	for _, p := range payloads {
		if !seen[p.Value] {
			seen[p.Value] = true
			unique = append(unique, p)
		}
	}
	return unique
}

// createFinding builds a Finding from a successful NoSQL injection
// signal. The detectionType argument identifies which arm of Detect
// produced the hit ("Error-based", "Boolean-based", "Time-based").
func (d *Detector) createFinding(target, param string, payload nosql.Payload, resp *http.Response, detectionType string) *core.Finding {
	finding := core.NewFinding("NoSQL Injection", core.SeverityCritical)
	finding.URL = target
	finding.Parameter = param
	finding.Description = fmt.Sprintf("%s NoSQL Injection vulnerability in '%s' parameter (Database: %s, Technique: %s)",
		detectionType, param, payload.DBType, payload.Technique)
	finding.Evidence = fmt.Sprintf("Payload: %s\nDescription: %s", payload.Value, payload.Description)
	finding.Tool = "nosqli-detector"

	if resp != nil && len(resp.Body) > 0 {
		body := resp.Body
		if len(body) > 500 {
			body = body[:500] + "..."
		}
		finding.Evidence += fmt.Sprintf("\nResponse snippet: %s", body)
	}

	finding.Remediation = "Use parameterized queries or prepared statements. " +
		"Never construct queries from user input directly. " +
		"Validate and sanitize all user input. " +
		"Use allowlists for valid inputs. " +
		"Disable JavaScript execution in MongoDB ($where, $function) if not needed. " +
		"Apply least privilege principle for database users."

	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-05"}, // Testing for NoSQL Injection
		[]string{"A05:2025"},     // Injection
		[]string{"CWE-943"},      // Improper Neutralization of Special Elements in Data Query Logic
	)

	return finding
}

package idor

import (
	"fmt"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

// calculateConfidence calculates confidence level based on evidence.
// Weighted score: SensitiveDataExposed dominates (2 pts) because it is
// the strongest unambiguous IDOR signal; status-change and content-diff
// contribute one each.
func (d *Detector) calculateConfidence(evidence *IDOREvidence) core.Confidence {
	score := 0

	if evidence.StatusCodeIndicatesAccess {
		score++
	}
	if evidence.ContentDifferent {
		score++
	}
	if evidence.SensitiveDataExposed {
		score += 2
	}

	switch {
	case score >= 3:
		return core.ConfidenceHigh
	case score >= 2:
		return core.ConfidenceMedium
	default:
		return core.ConfidenceLow
	}
}

// createFinding creates a Finding from IDOR detection evidence.
// Severity is High by default and bumps to Critical when sensitive data
// (PII / credentials / tokens) was leaked in the response body.
func (d *Detector) createFinding(targetURL string, param IDParameter, evidence *IDOREvidence, resp *http.Response) *core.Finding {
	severity := core.SeverityHigh
	if evidence.SensitiveDataExposed {
		severity = core.SeverityCritical
	}

	finding := core.NewFinding("Insecure Direct Object Reference (IDOR)", severity).At(targetURL, param.Name)
	finding.Tool = "idor-detector"
	finding.Confidence = d.calculateConfidence(evidence)

	finding.Description = fmt.Sprintf(
		"IDOR/BOLA vulnerability detected in parameter '%s' (Location: %s, Type: %s). "+
			"Successfully accessed resource with ID '%s' instead of original ID '%s'.",
		param.Name, param.Location, param.Type, evidence.TestedID, evidence.OriginalID)

	finding.Evidence = fmt.Sprintf(
		"Original ID: %s\nTested ID: %s\n"+
			"Original Status: %d\nTest Status: %d\n"+
			"Content Length Diff: %d bytes\n"+
			"Sensitive Data Exposed: %v\n\n"+
			"Response Snippet:\n%s",
		evidence.OriginalID, evidence.TestedID,
		evidence.OriginalStatusCode, evidence.TestedStatusCode,
		evidence.TestedContentLength-evidence.OriginalContentLength,
		evidence.SensitiveDataExposed,
		evidence.ResponseSnippet)

	finding.Remediation = "Implement proper authorization checks for all object references. " +
		"Verify that the authenticated user has permission to access the requested resource. " +
		"Use indirect references or access control lists (ACLs) instead of direct object IDs. " +
		"Consider using UUIDs instead of sequential IDs to make enumeration harder. " +
		"Log and monitor access attempts to detect potential attacks."

	finding.WithOWASPMapping(
		[]string{"WSTG-ATHZ-04"}, // Testing for Insecure Direct Object References
		[]string{"A01:2025"},     // Broken Access Control
		[]string{"CWE-639"},      // Authorization Bypass Through User-Controlled Key
	)
	finding.APITop10 = []string{"API1:2023"} // Broken Object Level Authorization

	finding.References = []string{
		"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
		"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
		"https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
		"https://cwe.mitre.org/data/definitions/639.html",
	}
	return finding
}

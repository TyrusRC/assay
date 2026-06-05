package integrations

import (
	"strings"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
)

func sampleFinding() *core.Finding {
	f := core.NewFinding("SQL Injection", core.SeverityCritical)
	f.Title = "SQL injection in login form"
	f.URL = "https://app.test/login"
	f.Parameter = "username"
	f.Description = "Boolean-based blind SQL injection."
	f.Evidence = "payload ' OR 1=1-- returned all rows"
	f.Remediation = "Use parameterized queries."
	f.CWE = []string{"CWE-89"}
	f.Top10 = []string{"A03:2025-Injection"}
	f.Confidence = core.ConfidenceConfirmed
	f.References = []string{"https://owasp.org/sqli"}
	return f
}

func TestFindingToIssue_TitleAndBody(t *testing.T) {
	iss := FindingToIssue(sampleFinding())
	if !strings.Contains(iss.Title, "SQL injection in login form") {
		t.Errorf("title should include finding title: %q", iss.Title)
	}
	if !strings.Contains(strings.ToLower(iss.Title), "critical") {
		t.Errorf("title should reflect severity: %q", iss.Title)
	}
	for _, want := range []string{
		"https://app.test/login", "username", "Boolean-based blind",
		"Use parameterized queries", "CWE-89", "A03:2025", "' OR 1=1--",
	} {
		if !strings.Contains(iss.Body, want) {
			t.Errorf("body missing %q\n---\n%s", want, iss.Body)
		}
	}
}

func TestFindingToIssue_Labels(t *testing.T) {
	iss := FindingToIssue(sampleFinding())
	has := func(l string) bool {
		for _, x := range iss.Labels {
			if x == l {
				return true
			}
		}
		return false
	}
	if !has("assay") || !has("security") {
		t.Errorf("expected base labels, got %v", iss.Labels)
	}
	if !has("severity:critical") {
		t.Errorf("expected severity label, got %v", iss.Labels)
	}
}

func TestFindingToIssue_FallsBackToType(t *testing.T) {
	f := core.NewFinding("Open Redirect", core.SeverityMedium)
	f.URL = "https://app.test/r"
	iss := FindingToIssue(f)
	if !strings.Contains(iss.Title, "Open Redirect") {
		t.Errorf("title should fall back to type: %q", iss.Title)
	}
}

func TestBuildIssues_FiltersByMinSeverity(t *testing.T) {
	findings := core.Findings{
		mkF("a", core.SeverityCritical),
		mkF("b", core.SeverityLow),
		mkF("c", core.SeverityHigh),
	}
	issues := BuildIssues(findings, core.SeverityHigh)
	if len(issues) != 2 {
		t.Fatalf("expected 2 issues at/above high, got %d", len(issues))
	}
}

func mkF(title string, sev core.Severity) *core.Finding {
	f := core.NewFinding("T", sev)
	f.Title = title
	f.URL = "https://app.test/" + title
	return f
}

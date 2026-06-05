package reporting

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/scanner"
)

type gitlabDocT struct {
	Version string `json:"version"`
	Scan    struct {
		Type    string `json:"type"`
		Status  string `json:"status"`
		Scanner struct {
			ID string `json:"id"`
		} `json:"scanner"`
	} `json:"scan"`
	Vulnerabilities []struct {
		ID          string `json:"id"`
		Category    string `json:"category"`
		Severity    string `json:"severity"`
		Identifiers []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifiers"`
		Location struct {
			Hostname string `json:"hostname"`
			Path     string `json:"path"`
			Param    string `json:"param"`
		} `json:"location"`
	} `json:"vulnerabilities"`
}

func sampleGitLab(t *testing.T) gitlabDocT {
	t.Helper()
	f := core.NewFinding("SQL Injection", core.SeverityCritical)
	f.URL = "https://example.com/app?id=1"
	f.Parameter = "id"
	f.Description = "SQLi in id"
	f.CWE = []string{"CWE-89"}

	r := NewReport(&scanner.ScanResult{
		Targets:  []string{"https://example.com"},
		Findings: core.Findings{f},
	})
	var buf bytes.Buffer
	if err := r.WriteGitLab(&buf); err != nil {
		t.Fatalf("WriteGitLab: %v", err)
	}
	var doc gitlabDocT
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("GitLab report is not valid JSON: %v", err)
	}
	return doc
}

func TestWriteGitLab_ScanMeta(t *testing.T) {
	doc := sampleGitLab(t)
	if doc.Version == "" {
		t.Error("missing version")
	}
	if doc.Scan.Type != "dast" || doc.Scan.Status != "success" {
		t.Errorf("scan = %+v, want type=dast status=success", doc.Scan)
	}
	if doc.Scan.Scanner.ID != "assay" {
		t.Errorf("scanner id = %q, want assay", doc.Scan.Scanner.ID)
	}
}

func TestWriteGitLab_VulnDetails(t *testing.T) {
	doc := sampleGitLab(t)
	if len(doc.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities = %d, want 1", len(doc.Vulnerabilities))
	}
	v := doc.Vulnerabilities[0]
	if v.Category != "dast" || v.Severity != "Critical" || v.ID == "" {
		t.Errorf("vuln meta = %+v, want dast/Critical/non-empty id", v)
	}
	if len(v.Identifiers) < 2 || v.Identifiers[1].Type != "cwe" || v.Identifiers[1].Value != "89" {
		t.Errorf("identifiers = %+v, want primary + cwe 89", v.Identifiers)
	}
	if v.Location.Hostname != "https://example.com" || v.Location.Path != "/app?id=1" || v.Location.Param != "id" {
		t.Errorf("location = %+v, want example.com /app?id=1 id", v.Location)
	}
}

func TestGitLabSeverity(t *testing.T) {
	cases := map[core.Severity]string{
		core.SeverityCritical:  "Critical",
		core.SeverityHigh:      "High",
		core.SeverityMedium:    "Medium",
		core.SeverityLow:       "Low",
		core.SeverityInfo:      "Info",
		core.Severity("weird"): "Unknown",
	}
	for in, want := range cases {
		if got := gitlabSeverity(in); got != want {
			t.Errorf("gitlabSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWriteGitLab_NoFindings(t *testing.T) {
	r := NewReport(&scanner.ScanResult{Targets: []string{"https://example.com"}})
	var buf bytes.Buffer
	if err := r.WriteGitLab(&buf); err != nil {
		t.Fatalf("WriteGitLab: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"vulnerabilities": []`)) {
		t.Error("expected empty vulnerabilities array for a clean scan")
	}
}

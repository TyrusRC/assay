package reporting

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/scanner"
)

type sarifDoc struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name           string `json:"name"`
				Version        string `json:"version"`
				InformationURI string `json:"informationUri"`
				Rules          []struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []sarifResultDoc `json:"results"`
	} `json:"runs"`
}

type sarifResultDoc struct {
	RuleID  string `json:"ruleId"`
	Level   string `json:"level"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
		} `json:"physicalLocation"`
	} `json:"locations"`
	Properties struct {
		SecuritySeverity string `json:"security-severity"`
	} `json:"properties"`
}

func sampleSARIF(t *testing.T) sarifDoc {
	t.Helper()
	crit := core.NewFinding("SQL Injection", core.SeverityCritical)
	crit.URL = "https://example.com/?id=1"
	crit.Parameter = "id"
	crit.Description = "SQLi in id"
	crit.CWE = []string{"CWE-89"}
	crit.References = []string{"https://owasp.org/sqli"}

	low := core.NewFinding("Missing Security Header", core.SeverityLow)
	low.URL = "https://example.com/"

	// Two findings of the same type must collapse to a single rule.
	dupe := core.NewFinding("SQL Injection", core.SeverityCritical)
	dupe.URL = "https://example.com/?id=2"
	dupe.Parameter = "id"

	r := NewReport(&scanner.ScanResult{
		Targets:  []string{"https://example.com"},
		Findings: core.Findings{crit, low, dupe},
	})

	var buf bytes.Buffer
	if err := r.WriteSARIF(&buf); err != nil {
		t.Fatalf("WriteSARIF error: %v", err)
	}
	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	return doc
}

func TestWriteSARIF_Structure(t *testing.T) {
	doc := sampleSARIF(t)
	if doc.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", doc.Version)
	}
	if doc.Schema == "" {
		t.Error("missing $schema")
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(doc.Runs))
	}
	driver := doc.Runs[0].Tool.Driver
	if driver.Name != "assay" {
		t.Errorf("driver name = %q, want assay", driver.Name)
	}
	if driver.InformationURI == "" {
		t.Error("missing driver informationUri")
	}
	// 3 findings, 2 distinct types → 2 rules.
	if len(driver.Rules) != 2 {
		t.Errorf("rules = %d, want 2 (deduped by type)", len(driver.Rules))
	}
	if len(doc.Runs[0].Results) != 3 {
		t.Errorf("results = %d, want 3", len(doc.Runs[0].Results))
	}
}

func TestWriteSARIF_ResultDetails(t *testing.T) {
	doc := sampleSARIF(t)
	res := doc.Runs[0].Results[0]
	if res.Level != "error" {
		t.Errorf("critical level = %q, want error", res.Level)
	}
	if res.Properties.SecuritySeverity != "9.8" {
		t.Errorf("security-severity = %q, want 9.8", res.Properties.SecuritySeverity)
	}
	if uri := res.Locations[0].PhysicalLocation.ArtifactLocation.URI; uri != "https://example.com/?id=1" {
		t.Errorf("location uri = %q", uri)
	}
	if res.RuleID == "" {
		t.Error("result missing ruleId")
	}

	var sawNote bool
	for _, r := range doc.Runs[0].Results {
		if r.Level == "note" {
			sawNote = true
		}
	}
	if !sawNote {
		t.Error("expected a low-severity result at level note")
	}
}

func TestWriteSARIF_NoFindings(t *testing.T) {
	r := NewReport(&scanner.ScanResult{Targets: []string{"https://example.com"}})
	var buf bytes.Buffer
	if err := r.WriteSARIF(&buf); err != nil {
		t.Fatalf("WriteSARIF error: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("empty SARIF is not valid JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", doc["version"])
	}
}

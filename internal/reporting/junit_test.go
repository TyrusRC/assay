package reporting

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/scanner"
)

type junitSuites struct {
	XMLName  xml.Name `xml:"testsuites"`
	Name     string   `xml:"name,attr"`
	Tests    int      `xml:"tests,attr"`
	Failures int      `xml:"failures,attr"`
	Suites   []struct {
		Name      string `xml:"name,attr"`
		Tests     int    `xml:"tests,attr"`
		Failures  int    `xml:"failures,attr"`
		TestCases []struct {
			Name      string `xml:"name,attr"`
			ClassName string `xml:"classname,attr"`
			Failure   *struct {
				Message string `xml:"message,attr"`
				Type    string `xml:"type,attr"`
				Body    string `xml:",chardata"`
			} `xml:"failure"`
		} `xml:"testcase"`
	} `xml:"testsuite"`
}

func TestWriteJUnit_Findings(t *testing.T) {
	f := core.NewFinding("SQL Injection", core.SeverityCritical)
	f.URL = "https://example.com/?id=1"
	f.Parameter = "id"
	f.Description = "SQLi in id"
	g := core.NewFinding("Missing Security Header", core.SeverityLow)
	g.URL = "https://example.com/"

	r := NewReport(&scanner.ScanResult{
		Targets:  []string{"https://example.com"},
		Findings: core.Findings{f, g},
	})

	var buf bytes.Buffer
	if err := r.WriteJUnit(&buf); err != nil {
		t.Fatalf("WriteJUnit error: %v", err)
	}
	if !strings.HasPrefix(buf.String(), "<?xml") {
		t.Error("missing XML declaration")
	}

	var doc junitSuites
	if err := xml.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("JUnit is not valid XML: %v", err)
	}
	if doc.Tests != 2 {
		t.Errorf("tests = %d, want 2", doc.Tests)
	}
	if doc.Failures != 2 {
		t.Errorf("failures = %d, want 2", doc.Failures)
	}
	if len(doc.Suites) != 1 {
		t.Fatalf("suites = %d, want 1", len(doc.Suites))
	}
	tcs := doc.Suites[0].TestCases
	if len(tcs) != 2 {
		t.Fatalf("testcases = %d, want 2", len(tcs))
	}
	if tcs[0].Failure == nil {
		t.Fatal("expected failure element on finding testcase")
	}
	if tcs[0].Failure.Type != "critical" {
		t.Errorf("failure type = %q, want critical", tcs[0].Failure.Type)
	}
	if !strings.Contains(tcs[0].Name, "SQL Injection") {
		t.Errorf("testcase name = %q, want it to mention the type", tcs[0].Name)
	}
}

func TestWriteJUnit_NoFindings(t *testing.T) {
	r := NewReport(&scanner.ScanResult{Targets: []string{"https://example.com"}})
	var buf bytes.Buffer
	if err := r.WriteJUnit(&buf); err != nil {
		t.Fatalf("WriteJUnit error: %v", err)
	}
	var doc junitSuites
	if err := xml.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("empty JUnit is not valid XML: %v", err)
	}
	// A clean scan must surface as a green suite, not an empty one.
	if doc.Failures != 0 {
		t.Errorf("failures = %d, want 0", doc.Failures)
	}
	if doc.Tests < 1 {
		t.Errorf("tests = %d, want >= 1 (a passing placeholder)", doc.Tests)
	}
}

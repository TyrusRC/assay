package compliance

import (
	"strings"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
)

func TestAssessment_WriteMarkdown(t *testing.T) {
	findings := core.Findings{
		finding("SQL Injection", "A03:2025-Injection"),
		finding("Broken Access Control", "A01:2025"),
		finding("Mystery", "Z99:2025"),
	}
	a := Assess(findings, PCIDSS)

	var sb strings.Builder
	if err := a.WriteMarkdown(&sb); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	out := sb.String()

	if !strings.Contains(out, "PCI-DSS v4.0") {
		t.Error("expected framework title in output")
	}
	if !strings.Contains(out, "PCI 6.2.4") {
		t.Error("expected the injection control ID")
	}
	if !strings.Contains(out, "SQL Injection") {
		t.Error("expected the finding title listed under its control")
	}
	if !strings.Contains(strings.ToLower(out), "unmapped") {
		t.Error("expected an unmapped section for the Z99 finding")
	}
}

func TestAssessment_WriteJSON(t *testing.T) {
	a := Assess(core.Findings{finding("x", "A01:2025")}, ISO27001)
	var sb strings.Builder
	if err := a.WriteJSON(&sb); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	out := sb.String()
	if !strings.Contains(out, "iso-27001") || !strings.Contains(out, "A.5.15") {
		t.Errorf("expected framework and control in JSON: %s", out)
	}
}

func TestAssessment_WriteMarkdown_CleanScan(t *testing.T) {
	a := Assess(core.Findings{}, HIPAA)
	var sb strings.Builder
	if err := a.WriteMarkdown(&sb); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	if !strings.Contains(sb.String(), "No findings") {
		t.Error("expected a clean-scan note when there are no findings")
	}
}

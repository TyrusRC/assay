package reporting

import (
	"testing"

	"github.com/TyrusRC/assay/internal/core"
)

func sampleFindings() core.Findings {
	a := core.NewFinding("SQL Injection", core.SeverityCritical)
	a.Top10 = []string{"A03:2021"}
	a.CVSS = 9.8
	b := core.NewFinding("Reflected XSS", core.SeverityHigh)
	b.Top10 = []string{"A03:2021"}
	b.CVSS = 6.1
	c := core.NewFinding("Missing Security Header", core.SeverityLow)
	c.Top10 = []string{"A05:2025-Security Misconfiguration"}
	c.CVSS = 3.1
	return core.Findings{a, b, c}
}

func TestComputeStats(t *testing.T) {
	s := computeStats(sampleFindings())
	if s.Total != 3 {
		t.Errorf("Total = %d, want 3", s.Total)
	}
	if s.BySeverity[core.SeverityCritical] != 1 || s.BySeverity[core.SeverityHigh] != 1 {
		t.Errorf("BySeverity wrong: %+v", s.BySeverity)
	}
	if s.HighestCVSS != 9.8 {
		t.Errorf("HighestCVSS = %v, want 9.8", s.HighestCVSS)
	}
	if s.ByType["SQL Injection"] != 1 {
		t.Errorf("ByType[SQL Injection] = %d, want 1", s.ByType["SQL Injection"])
	}
	if s.OWASPCoverage["A03"] != 2 {
		t.Errorf("OWASPCoverage[A03] = %d, want 2", s.OWASPCoverage["A03"])
	}
	if s.OWASPCoverage["A05"] != 1 {
		t.Errorf("OWASPCoverage[A05] = %d, want 1", s.OWASPCoverage["A05"])
	}
}

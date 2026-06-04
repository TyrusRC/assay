package scoring

import (
	"testing"

	"github.com/TyrusRC/assay/internal/core"
)

func TestEnrich_FillsZeroCVSS(t *testing.T) {
	f := core.NewFinding("SQL Injection", core.SeverityCritical)
	f.CWE = []string{"CWE-89"}
	Enrich(core.Findings{f})
	if f.CVSS < 9.0 {
		t.Errorf("CVSS = %v, want >= 9.0", f.CVSS)
	}
	if f.CVSSVector == "" {
		t.Error("CVSSVector should be set after Enrich")
	}
}

func TestEnrich_PreservesExternalScore(t *testing.T) {
	f := core.NewFinding("Vulnerable Dependency", core.SeverityHigh)
	f.CVSS = 7.3 // externally provided (e.g. NVD)
	Enrich(core.Findings{f})
	if f.CVSS != 7.3 {
		t.Errorf("external CVSS overwritten: got %v, want 7.3", f.CVSS)
	}
	if f.CVSSVector != "" {
		t.Errorf("should not synthesize a vector for an external score, got %q", f.CVSSVector)
	}
}

func TestEnrich_InfoNoMappingStaysZero(t *testing.T) {
	f := core.NewFinding("Informational", core.SeverityInfo)
	Enrich(core.Findings{f})
	if f.CVSS != 0.0 {
		t.Errorf("Info CVSS = %v, want 0.0", f.CVSS)
	}
}

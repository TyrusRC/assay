package compliance

import (
	"testing"

	"github.com/TyrusRC/assay/internal/core"
)

func finding(vulnType string, top10 ...string) *core.Finding {
	f := core.NewFinding(vulnType, core.SeverityHigh)
	f.URL = "https://app.test/x"
	f.Top10 = top10
	return f
}

func TestParseFramework(t *testing.T) {
	cases := map[string]Framework{
		"pci": PCIDSS, "pci-dss": PCIDSS, "PCI-DSS": PCIDSS,
		"hipaa": HIPAA, "iso": ISO27001, "iso-27001": ISO27001, "iso27001": ISO27001,
	}
	for in, want := range cases {
		got, err := ParseFramework(in)
		if err != nil || got != want {
			t.Errorf("ParseFramework(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseFramework("sox"); err == nil {
		t.Error("expected error for unknown framework")
	}
}

func TestAssess_MapsOWASPToControls(t *testing.T) {
	findings := core.Findings{
		finding("SQL Injection", "A03:2025-Injection"),
		finding("Broken Access Control", "A01:2025"),
	}
	a := Assess(findings, PCIDSS)
	if a.Framework != PCIDSS {
		t.Fatalf("framework = %v", a.Framework)
	}
	if len(a.Requirements) == 0 {
		t.Fatal("expected mapped requirements")
	}
	// Every requirement must carry at least one finding and a non-empty control.
	total := 0
	for _, r := range a.Requirements {
		if r.Control.ID == "" || r.Control.Title == "" {
			t.Errorf("requirement has empty control: %+v", r)
		}
		if len(r.Findings) == 0 {
			t.Errorf("requirement %s has no findings", r.Control.ID)
		}
		total += len(r.Findings)
	}
	if total < 2 {
		t.Errorf("expected both findings mapped, got %d finding-slots", total)
	}
}

func TestAssess_UnmappedFindingsTracked(t *testing.T) {
	findings := core.Findings{finding("Mystery", "Z99:2025-Nope")}
	a := Assess(findings, ISO27001)
	if len(a.Unmapped) != 1 {
		t.Fatalf("expected 1 unmapped finding, got %d", len(a.Unmapped))
	}
}

func TestAssess_AllFrameworksHaveInjectionMapping(t *testing.T) {
	inj := core.Findings{finding("SQL Injection", "A03:2025-Injection")}
	for _, fw := range Frameworks() {
		a := Assess(inj, fw)
		if len(a.Requirements) == 0 {
			t.Errorf("framework %s has no mapping for injection (A03)", fw)
		}
		if len(a.Unmapped) != 0 {
			t.Errorf("framework %s left injection unmapped", fw)
		}
	}
}

func TestMapFinding_DeduplicatesControls(t *testing.T) {
	// A finding tagged with two categories that map to the same control must
	// not yield duplicate controls.
	f := finding("x", "A01:2025", "A07:2025")
	controls := MapFinding(f, ISO27001)
	seen := map[string]bool{}
	for _, c := range controls {
		if seen[c.ID] {
			t.Errorf("duplicate control %s", c.ID)
		}
		seen[c.ID] = true
	}
}

func TestOWASPCategory(t *testing.T) {
	cases := map[string]string{
		"A01:2025-Broken Access Control": "A01",
		"A10:2025":                       "A10",
		"A3:2025":                        "A03",
		"garbage":                        "",
	}
	for in, want := range cases {
		if got := owaspCategory(in); got != want {
			t.Errorf("owaspCategory(%q) = %q, want %q", in, got, want)
		}
	}
}

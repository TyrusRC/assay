package scoring

import (
	"testing"

	"github.com/TyrusRC/assay/internal/core"
)

func TestDefaultVector_ByCWE(t *testing.T) {
	v := DefaultVector([]string{"CWE-89"}, core.SeverityCritical)
	m, err := ParseVector(v)
	if err != nil {
		t.Fatalf("CWE-89 vector %q does not parse: %v", v, err)
	}
	if got := m.BaseScore(); got < 9.0 {
		t.Errorf("CWE-89 score = %v, want >= 9.0", got)
	}
}

func TestDefaultVector_SeverityFallback(t *testing.T) {
	tests := []struct {
		sev     core.Severity
		wantMin float64
		wantMax float64
	}{
		{core.SeverityCritical, 9.0, 10.0},
		{core.SeverityHigh, 7.0, 8.9},
		{core.SeverityMedium, 4.0, 6.9},
		{core.SeverityLow, 0.1, 3.9},
		{core.SeverityInfo, 0.0, 0.0},
	}
	for _, tt := range tests {
		v := DefaultVector([]string{"CWE-99999"}, tt.sev)
		if tt.sev == core.SeverityInfo {
			if v != "" {
				m, _ := ParseVector(v)
				if m.BaseScore() != 0.0 {
					t.Errorf("Info fallback score = %v, want 0.0", m.BaseScore())
				}
			}
			continue
		}
		m, err := ParseVector(v)
		if err != nil {
			t.Fatalf("fallback vector %q does not parse: %v", v, err)
		}
		got := m.BaseScore()
		if got < tt.wantMin || got > tt.wantMax {
			t.Errorf("%v fallback score = %v, want [%v,%v]", tt.sev, got, tt.wantMin, tt.wantMax)
		}
	}
}

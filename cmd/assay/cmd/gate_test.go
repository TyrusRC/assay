package cmd

import (
	"errors"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
)

func mkFindings(sevs ...core.Severity) core.Findings {
	var fs core.Findings
	for _, s := range sevs {
		f := core.NewFinding("Test", s)
		f.URL = "https://example.com/"
		fs = append(fs, f)
	}
	return fs
}

func TestEvaluateGate(t *testing.T) {
	tests := []struct {
		name      string
		failOn    string
		findings  core.Findings
		wantFail  bool
		wantCount int
		wantErr   bool
	}{
		{"disabled empty", "", mkFindings(core.SeverityCritical), false, 0, false},
		{"disabled none", "none", mkFindings(core.SeverityCritical), false, 0, false},
		{"high gate critical finding", "high", mkFindings(core.SeverityCritical, core.SeverityLow), true, 1, false},
		{"high gate high finding", "high", mkFindings(core.SeverityHigh), true, 1, false},
		{"critical gate high finding", "critical", mkFindings(core.SeverityHigh), false, 0, false},
		{"low gate counts all but info", "low", mkFindings(core.SeverityCritical, core.SeverityLow, core.SeverityInfo), true, 2, false},
		{"no findings", "high", nil, false, 0, false},
		{"invalid threshold", "bogus", mkFindings(core.SeverityHigh), false, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fail, count, err := evaluateGate(tt.findings, tt.failOn)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if fail != tt.wantFail {
				t.Errorf("fail = %v, want %v", fail, tt.wantFail)
			}
			if count != tt.wantCount {
				t.Errorf("count = %d, want %d", count, tt.wantCount)
			}
		})
	}
}

func TestExitCode(t *testing.T) {
	if got := ExitCode(nil); got != 0 {
		t.Errorf("ExitCode(nil) = %d, want 0", got)
	}
	if got := ExitCode(errors.New("boom")); got != 1 {
		t.Errorf("ExitCode(generic) = %d, want 1", got)
	}
	if got := ExitCode(&gateError{Threshold: core.SeverityHigh, Count: 2}); got != gateExitCode {
		t.Errorf("ExitCode(gateError) = %d, want %d", got, gateExitCode)
	}
}

func TestGateError_IsTyped(t *testing.T) {
	err := &gateError{Threshold: core.SeverityHigh, Count: 3}
	var ge *gateError
	if !errors.As(err, &ge) {
		t.Fatal("gateError should be detectable via errors.As")
	}
	if ge.Count != 3 {
		t.Errorf("Count = %d, want 3", ge.Count)
	}
	if err.Error() == "" {
		t.Error("gateError should have a message")
	}
}

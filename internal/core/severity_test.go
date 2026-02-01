package core

import "testing"

func TestSeverity_String(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		want     string
	}{
		{"critical", SeverityCritical, "critical"},
		{"high", SeverityHigh, "high"},
		{"medium", SeverityMedium, "medium"},
		{"low", SeverityLow, "low"},
		{"info", SeverityInfo, "info"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.severity.String(); got != tt.want {
				t.Errorf("Severity.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSeverity_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		want     bool
	}{
		{"critical is valid", SeverityCritical, true},
		{"high is valid", SeverityHigh, true},
		{"medium is valid", SeverityMedium, true},
		{"low is valid", SeverityLow, true},
		{"info is valid", SeverityInfo, true},
		{"empty is invalid", Severity(""), false},
		{"unknown is invalid", Severity("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.severity.IsValid(); got != tt.want {
				t.Errorf("Severity.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Severity
		wantErr bool
	}{
		{"critical", "critical", SeverityCritical, false},
		{"CRITICAL uppercase", "CRITICAL", SeverityCritical, false},
		{"high", "high", SeverityHigh, false},
		{"medium", "medium", SeverityMedium, false},
		{"low", "low", SeverityLow, false},
		{"info", "info", SeverityInfo, false},
		{"informational alias", "informational", SeverityInfo, false},
		{"invalid", "invalid", "", true},
		{"empty", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSeverity(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSeverity() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseSeverity() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSeverity_Score(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		want     int
	}{
		{"critical", SeverityCritical, 5},
		{"high", SeverityHigh, 4},
		{"medium", SeverityMedium, 3},
		{"low", SeverityLow, 2},
		{"info", SeverityInfo, 1},
		{"invalid", Severity("invalid"), 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.severity.Score(); got != tt.want {
				t.Errorf("Severity.Score() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfidence_String(t *testing.T) {
	tests := []struct {
		name       string
		confidence Confidence
		want       string
	}{
		{"confirmed", ConfidenceConfirmed, "confirmed"},
		{"high", ConfidenceHigh, "high"},
		{"medium", ConfidenceMedium, "medium"},
		{"low", ConfidenceLow, "low"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.confidence.String(); got != tt.want {
				t.Errorf("Confidence.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfidence_IsValid(t *testing.T) {
	tests := []struct {
		name       string
		confidence Confidence
		want       bool
	}{
		{"confirmed is valid", ConfidenceConfirmed, true},
		{"high is valid", ConfidenceHigh, true},
		{"medium is valid", ConfidenceMedium, true},
		{"low is valid", ConfidenceLow, true},
		{"empty is invalid", Confidence(""), false},
		{"unknown is invalid", Confidence("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.confidence.IsValid(); got != tt.want {
				t.Errorf("Confidence.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

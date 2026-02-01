package exposure

import (
	"testing"
)

func TestGetPayloads(t *testing.T) {
	payloads := GetPayloads()
	if len(payloads) == 0 {
		t.Error("GetPayloads returned no payloads")
	}

	for i, p := range payloads {
		if p.Path == "" {
			t.Errorf("Payload %d has empty Path", i)
		}
		if p.Category == "" {
			t.Errorf("Payload %d (%s) has empty Category", i, p.Path)
		}
		if p.Severity == "" {
			t.Errorf("Payload %d (%s) has empty Severity", i, p.Path)
		}
		if p.Description == "" {
			t.Errorf("Payload %d (%s) has empty Description", i, p.Path)
		}
	}
}

func TestGetByCategory(t *testing.T) {
	tests := []struct {
		name     string
		category Category
		minCount int
	}{
		{"config", CategoryConfig, 5},
		{"version_control", CategoryVersionCtrl, 3},
		{"backup", CategoryBackup, 3},
		{"debug", CategoryDebug, 3},
		{"secret", CategorySecret, 5},
		{"log", CategoryLog, 3},
		{"ide", CategoryIDE, 2},
		{"database", CategoryDatabase, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := GetByCategory(tt.category)
			if len(payloads) < tt.minCount {
				t.Errorf("GetByCategory(%s) returned %d payloads, want at least %d", tt.category, len(payloads), tt.minCount)
			}
			for _, p := range payloads {
				if p.Category != tt.category {
					t.Errorf("GetByCategory(%s) returned payload with Category %s", tt.category, p.Category)
				}
			}
		})
	}
}

func TestGetByCategory_UnknownCategory(t *testing.T) {
	payloads := GetByCategory(Category("nonexistent"))
	if len(payloads) != 0 {
		t.Errorf("GetByCategory with unknown category returned %d payloads, want 0", len(payloads))
	}
}

func TestGetBySeverity(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		minCount int
	}{
		{"critical", SeverityCritical, 5},
		{"high", SeverityHigh, 5},
		{"medium", SeverityMedium, 3},
		{"low", SeverityLow, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := GetBySeverity(tt.severity)
			if len(payloads) < tt.minCount {
				t.Errorf("GetBySeverity(%s) returned %d payloads, want at least %d", tt.severity, len(payloads), tt.minCount)
			}
			for _, p := range payloads {
				if p.Severity != tt.severity {
					t.Errorf("GetBySeverity(%s) returned payload with Severity %s", tt.severity, p.Severity)
				}
			}
		})
	}
}

func TestGetBySeverity_UnknownSeverity(t *testing.T) {
	payloads := GetBySeverity(Severity("nonexistent"))
	if len(payloads) != 0 {
		t.Errorf("GetBySeverity with unknown severity returned %d payloads, want 0", len(payloads))
	}
}

func TestGetCriticalPayloads(t *testing.T) {
	payloads := GetCriticalPayloads()
	if len(payloads) == 0 {
		t.Error("GetCriticalPayloads returned no payloads")
	}
	for _, p := range payloads {
		if p.Severity != SeverityCritical {
			t.Errorf("GetCriticalPayloads returned payload with Severity %s: %s", p.Severity, p.Path)
		}
	}
}

func TestGetConfigPayloads(t *testing.T) {
	payloads := GetConfigPayloads()
	if len(payloads) == 0 {
		t.Error("GetConfigPayloads returned no payloads")
	}
	for _, p := range payloads {
		if p.Category != CategoryConfig {
			t.Errorf("GetConfigPayloads returned payload with Category %s: %s", p.Category, p.Path)
		}
	}
}

func TestGetSecretPayloads(t *testing.T) {
	payloads := GetSecretPayloads()
	if len(payloads) == 0 {
		t.Error("GetSecretPayloads returned no payloads")
	}
	for _, p := range payloads {
		if p.Category != CategorySecret {
			t.Errorf("GetSecretPayloads returned payload with Category %s: %s", p.Category, p.Path)
		}
	}
}

func TestPayloadValidCategories(t *testing.T) {
	payloads := GetPayloads()
	validCategories := map[Category]bool{
		CategoryConfig:      true,
		CategoryVersionCtrl: true,
		CategoryBackup:      true,
		CategoryDebug:       true,
		CategorySecret:      true,
		CategoryLog:         true,
		CategoryIDE:         true,
		CategoryDatabase:    true,
	}

	for _, p := range payloads {
		if !validCategories[p.Category] {
			t.Errorf("Invalid category %s for payload %s", p.Category, p.Path)
		}
	}
}

func TestPayloadValidSeverities(t *testing.T) {
	payloads := GetPayloads()
	validSeverities := map[Severity]bool{
		SeverityCritical: true,
		SeverityHigh:     true,
		SeverityMedium:   true,
		SeverityLow:      true,
	}

	for _, p := range payloads {
		if !validSeverities[p.Severity] {
			t.Errorf("Invalid severity %s for payload %s", p.Severity, p.Path)
		}
	}
}

func TestNoDuplicatePayloads(t *testing.T) {
	all := GetPayloads()
	seen := make(map[string]bool)
	duplicates := 0

	for _, p := range all {
		if seen[p.Path] {
			duplicates++
			if duplicates <= 3 {
				t.Logf("Duplicate path found: %s", p.Path)
			}
		}
		seen[p.Path] = true
	}

	if duplicates > 0 {
		t.Errorf("Found %d duplicate paths", duplicates)
	}
}

func TestCriticalPayloadsMatchBySeverity(t *testing.T) {
	critical := GetCriticalPayloads()
	bySeverity := GetBySeverity(SeverityCritical)

	if len(critical) != len(bySeverity) {
		t.Errorf("GetCriticalPayloads returned %d, GetBySeverity(critical) returned %d", len(critical), len(bySeverity))
	}
}

func TestConfigPayloadsMatchByCategory(t *testing.T) {
	config := GetConfigPayloads()
	byCategory := GetByCategory(CategoryConfig)

	if len(config) != len(byCategory) {
		t.Errorf("GetConfigPayloads returned %d, GetByCategory(config) returned %d", len(config), len(byCategory))
	}
}

func TestSecretPayloadsMatchByCategory(t *testing.T) {
	secrets := GetSecretPayloads()
	byCategory := GetByCategory(CategorySecret)

	if len(secrets) != len(byCategory) {
		t.Errorf("GetSecretPayloads returned %d, GetByCategory(secret) returned %d", len(secrets), len(byCategory))
	}
}

func TestAllCategoriesHavePayloads(t *testing.T) {
	categories := []Category{
		CategoryConfig, CategoryVersionCtrl, CategoryBackup,
		CategoryDebug, CategorySecret, CategoryLog, CategoryIDE, CategoryDatabase,
	}

	for _, cat := range categories {
		payloads := GetByCategory(cat)
		if len(payloads) == 0 {
			t.Errorf("Category %s has no payloads", cat)
		}
	}
}

func TestAllSeveritiesHavePayloads(t *testing.T) {
	severities := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}

	for _, sev := range severities {
		payloads := GetBySeverity(sev)
		if len(payloads) == 0 {
			t.Errorf("Severity %s has no payloads", sev)
		}
	}
}

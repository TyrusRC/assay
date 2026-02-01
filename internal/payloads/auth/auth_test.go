package auth

import (
	"testing"
)

func TestGetDefaultCredentials(t *testing.T) {
	creds := GetDefaultCredentials()
	if len(creds) == 0 {
		t.Error("GetDefaultCredentials returned no credentials")
	}

	for i, c := range creds {
		if c.Username == "" {
			t.Errorf("Credential %d has empty Username", i)
		}
		if c.Service == "" {
			t.Errorf("Credential %d (%s) has empty Service", i, c.Username)
		}
		if c.Description == "" {
			t.Errorf("Credential %d (%s) has empty Description", i, c.Username)
		}
	}
}

func TestGetByService(t *testing.T) {
	tests := []struct {
		name     string
		service  string
		minCount int
	}{
		{"generic", "generic", 5},
		{"mysql", "mysql", 1},
		{"mssql", "mssql", 1},
		{"postgresql", "postgresql", 1},
		{"router", "router", 1},
		{"cisco", "cisco", 1},
		{"wordpress", "wordpress", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds := GetByService(tt.service)
			if len(creds) < tt.minCount {
				t.Errorf("GetByService(%s) returned %d credentials, want at least %d", tt.service, len(creds), tt.minCount)
			}
			for _, c := range creds {
				if c.Service != tt.service {
					t.Errorf("GetByService(%s) returned credential with Service %s", tt.service, c.Service)
				}
			}
		})
	}
}

func TestGetByService_UnknownService(t *testing.T) {
	creds := GetByService("nonexistent_service_xyz")
	if len(creds) != 0 {
		t.Errorf("GetByService with unknown service returned %d credentials, want 0", len(creds))
	}
}

func TestGetEnumerationPayloads(t *testing.T) {
	payloads := GetEnumerationPayloads()
	if len(payloads) == 0 {
		t.Error("GetEnumerationPayloads returned no payloads")
	}

	for i, p := range payloads {
		if p.ValidUser == "" {
			t.Errorf("EnumerationPayload %d has empty ValidUser", i)
		}
		if p.InvalidUser == "" {
			t.Errorf("EnumerationPayload %d has empty InvalidUser", i)
		}
		if p.Description == "" {
			t.Errorf("EnumerationPayload %d has empty Description", i)
		}
		if p.ValidUser == p.InvalidUser {
			t.Errorf("EnumerationPayload %d has same ValidUser and InvalidUser: %s", i, p.ValidUser)
		}
	}
}

func TestGetPasswordPolicyChecks(t *testing.T) {
	checks := GetPasswordPolicyChecks()
	if len(checks) == 0 {
		t.Error("GetPasswordPolicyChecks returned no checks")
	}

	for i, c := range checks {
		if c.Password == "" {
			t.Errorf("PasswordPolicyCheck %d has empty Password", i)
		}
		if c.Weakness == "" {
			t.Errorf("PasswordPolicyCheck %d has empty Weakness", i)
		}
		if c.Description == "" {
			t.Errorf("PasswordPolicyCheck %d has empty Description", i)
		}
	}
}

func TestDefaultCredentialFields(t *testing.T) {
	creds := GetDefaultCredentials()
	services := make(map[string]bool)
	for _, c := range creds {
		services[c.Service] = true
	}

	expectedServices := []string{"generic", "mysql", "mssql", "postgresql", "router", "cisco"}
	for _, svc := range expectedServices {
		if !services[svc] {
			t.Errorf("No credentials found for service %s", svc)
		}
	}
}

func TestNoDuplicateCredentials(t *testing.T) {
	creds := GetDefaultCredentials()
	seen := make(map[string]bool)
	duplicates := 0

	for _, c := range creds {
		key := c.Username + "|" + c.Password + "|" + c.Service
		if seen[key] {
			duplicates++
			if duplicates <= 3 {
				t.Logf("Duplicate credential found: %s:%s (%s)", c.Username, c.Password, c.Service)
			}
		}
		seen[key] = true
	}

	if duplicates > 0 {
		t.Errorf("Found %d duplicate credentials", duplicates)
	}
}

func TestPasswordPolicyWeaknessTypes(t *testing.T) {
	checks := GetPasswordPolicyChecks()
	validWeaknesses := map[string]bool{
		"too_short":     true,
		"common":        true,
		"numeric_only":  true,
		"no_complexity": true,
	}

	for _, c := range checks {
		if !validWeaknesses[c.Weakness] {
			t.Errorf("Unknown weakness type %q for password %q", c.Weakness, c.Password)
		}
	}
}

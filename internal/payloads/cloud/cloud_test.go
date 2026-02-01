package cloud

import (
	"strings"
	"testing"
)

func TestGetBucketChecks(t *testing.T) {
	checks := GetBucketChecks()
	if len(checks) == 0 {
		t.Error("GetBucketChecks returned no checks")
	}

	for i, c := range checks {
		if c.URLTemplate == "" {
			t.Errorf("BucketCheck %d has empty URLTemplate", i)
		}
		if c.Provider == "" {
			t.Errorf("BucketCheck %d has empty Provider", i)
		}
		if c.Resource == "" {
			t.Errorf("BucketCheck %d has empty Resource", i)
		}
		if c.Description == "" {
			t.Errorf("BucketCheck %d has empty Description", i)
		}
		if len(c.Patterns) == 0 {
			t.Errorf("BucketCheck %d (%s) has no Patterns", i, c.Description)
		}
	}
}

func TestGetByProvider(t *testing.T) {
	tests := []struct {
		name     string
		provider Provider
		minCount int
	}{
		{"AWS", ProviderAWS, 2},
		{"GCP", ProviderGCP, 2},
		{"Azure", ProviderAzure, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checks := GetByProvider(tt.provider)
			if len(checks) < tt.minCount {
				t.Errorf("GetByProvider(%s) returned %d checks, want at least %d", tt.provider, len(checks), tt.minCount)
			}
			for _, c := range checks {
				if c.Provider != tt.provider {
					t.Errorf("GetByProvider(%s) returned check with Provider %s", tt.provider, c.Provider)
				}
			}
		})
	}
}

func TestGetByProvider_UnknownProvider(t *testing.T) {
	checks := GetByProvider(Provider("unknown"))
	if len(checks) != 0 {
		t.Errorf("GetByProvider with unknown provider returned %d checks, want 0", len(checks))
	}
}

func TestGetCommonBucketNames(t *testing.T) {
	names := GetCommonBucketNames()
	if len(names) == 0 {
		t.Error("GetCommonBucketNames returned no names")
	}

	for i, name := range names {
		if name == "" {
			t.Errorf("CommonBucketName %d is empty", i)
		}
		if !strings.Contains(name, "{DOMAIN}") {
			t.Errorf("CommonBucketName %d (%s) does not contain {DOMAIN} placeholder", i, name)
		}
	}
}

func TestBucketChecksHaveValidProviders(t *testing.T) {
	checks := GetBucketChecks()
	validProviders := map[Provider]bool{
		ProviderAWS:   true,
		ProviderGCP:   true,
		ProviderAzure: true,
	}

	for _, c := range checks {
		if !validProviders[c.Provider] {
			t.Errorf("Invalid provider %s for check %s", c.Provider, c.Description)
		}
	}
}

func TestBucketChecksHaveValidResourceTypes(t *testing.T) {
	checks := GetBucketChecks()
	validResources := map[ResourceType]bool{
		ResourceBucket:   true,
		ResourceBlob:     true,
		ResourceFunction: true,
		ResourceAPI:      true,
	}

	for _, c := range checks {
		if !validResources[c.Resource] {
			t.Errorf("Invalid resource type %s for check %s", c.Resource, c.Description)
		}
	}
}

func TestAWSChecksContainS3URLs(t *testing.T) {
	awsChecks := GetByProvider(ProviderAWS)
	for _, c := range awsChecks {
		if !strings.Contains(c.URLTemplate, "amazonaws.com") {
			t.Errorf("AWS check %q has URL without amazonaws.com: %s", c.Description, c.URLTemplate)
		}
	}
}

func TestGCPChecksContainGoogleURLs(t *testing.T) {
	gcpChecks := GetByProvider(ProviderGCP)
	for _, c := range gcpChecks {
		if !strings.Contains(c.URLTemplate, "googleapis.com") {
			t.Errorf("GCP check %q has URL without googleapis.com: %s", c.Description, c.URLTemplate)
		}
	}
}

func TestAzureChecksContainWindowsURLs(t *testing.T) {
	azureChecks := GetByProvider(ProviderAzure)
	for _, c := range azureChecks {
		if !strings.Contains(c.URLTemplate, "windows.net") {
			t.Errorf("Azure check %q has URL without windows.net: %s", c.Description, c.URLTemplate)
		}
	}
}

func TestNoDuplicateBucketChecks(t *testing.T) {
	checks := GetBucketChecks()
	seen := make(map[string]bool)
	duplicates := 0

	for _, c := range checks {
		key := c.URLTemplate + "|" + string(c.Provider)
		if seen[key] {
			duplicates++
			if duplicates <= 3 {
				t.Logf("Duplicate bucket check found: %s (%s)", c.URLTemplate, c.Provider)
			}
		}
		seen[key] = true
	}

	if duplicates > 0 {
		t.Errorf("Found %d duplicate bucket checks", duplicates)
	}
}

func TestAllProvidersHaveChecks(t *testing.T) {
	providers := []Provider{ProviderAWS, ProviderGCP, ProviderAzure}
	for _, p := range providers {
		checks := GetByProvider(p)
		if len(checks) == 0 {
			t.Errorf("No checks found for provider %s", p)
		}
	}
}

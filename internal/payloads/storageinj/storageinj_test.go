package storageinj

import (
	"testing"
)

func TestGetPayloads(t *testing.T) {
	tests := []struct {
		storageType StorageType
		minCount    int
	}{
		{LocalStorage, 2},
		{SessionStorage, 2},
		{Cookie, 2},
		{WindowName, 2},
	}

	for _, tt := range tests {
		t.Run(string(tt.storageType), func(t *testing.T) {
			payloads := GetPayloads(tt.storageType)
			if len(payloads) < tt.minCount {
				t.Errorf("GetPayloads(%q) count = %d, want >= %d", tt.storageType, len(payloads), tt.minCount)
			}
			for _, p := range payloads {
				if p.StorageType != tt.storageType {
					t.Errorf("payload StorageType = %q, want %q", p.StorageType, tt.storageType)
				}
				if p.Value == "" {
					t.Error("payload Value is empty")
				}
				if p.Marker == "" {
					t.Error("payload Marker is empty")
				}
				if p.Description == "" {
					t.Error("payload Description is empty")
				}
			}
		})
	}
}

func TestGetAllPayloads(t *testing.T) {
	all := GetAllPayloads()
	if len(all) == 0 {
		t.Fatal("GetAllPayloads() returned empty")
	}

	// Verify it's a copy
	all[0].Value = "modified"
	original := GetAllPayloads()
	if original[0].Value == "modified" {
		t.Error("GetAllPayloads() should return a copy")
	}
}

func TestStorageTypes(t *testing.T) {
	types := StorageTypes()
	if len(types) != 4 {
		t.Errorf("StorageTypes() count = %d, want 4", len(types))
	}

	expected := map[StorageType]bool{
		LocalStorage: true, SessionStorage: true,
		Cookie: true, WindowName: true,
	}
	for _, st := range types {
		if !expected[st] {
			t.Errorf("unexpected StorageType: %q", st)
		}
	}
}

func TestPayloadMarkersUnique(t *testing.T) {
	all := GetAllPayloads()
	markers := make(map[string]bool)
	for _, p := range all {
		if markers[p.Marker] {
			t.Errorf("duplicate marker: %q", p.Marker)
		}
		markers[p.Marker] = true
	}
}

func TestSensitiveKeyPatterns(t *testing.T) {
	if len(SensitiveKeyPatterns) == 0 {
		t.Fatal("SensitiveKeyPatterns is empty")
	}

	expectedPatterns := []string{"token", "jwt", "password", "api_key", "session"}
	for _, expected := range expectedPatterns {
		found := false
		for _, pattern := range SensitiveKeyPatterns {
			if pattern == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing expected pattern: %q", expected)
		}
	}
}

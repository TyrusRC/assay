package oob

import (
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/server"
)

// TestClient_RecordInteraction_NoDrop verifies that large bursts of incoming
// interactions are all persisted, not silently dropped. Before the fix, a
// buffered channel with `default:` drop discarded anything over 100 entries.
func TestClient_RecordInteraction_NoDrop(t *testing.T) {
	c := &Client{
		payloads:     map[string]*Payload{"abc": {ID: "abc", Type: "sqli"}},
		interactions: make([]*Interaction, 0),
	}

	const n = 500 // much larger than the old 100-slot buffer
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.recordInteraction(&server.Interaction{
				FullId:        "abc.oast.fun",
				Protocol:      "dns",
				RemoteAddress: "1.2.3.4",
				Timestamp:     time.Now(),
			})
		}()
	}
	wg.Wait()

	c.mu.RLock()
	got := len(c.interactions)
	c.mu.RUnlock()
	if got != n {
		t.Errorf("recorded %d interactions, want %d (drop or race)", got, n)
	}
}

func TestPayload_DNSPayload(t *testing.T) {
	tests := []struct {
		name    string
		payload Payload
		want    string
	}{
		{
			name:    "with http prefix",
			payload: Payload{URL: "http://abc123.oast.fun"},
			want:    "abc123.oast.fun",
		},
		{
			name:    "with https prefix",
			payload: Payload{URL: "https://abc123.oast.fun"},
			want:    "abc123.oast.fun",
		},
		{
			name:    "without prefix",
			payload: Payload{URL: "abc123.oast.fun"},
			want:    "abc123.oast.fun",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.payload.DNSPayload()
			if got != tt.want {
				t.Errorf("DNSPayload() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPayload_HTTPPayload(t *testing.T) {
	tests := []struct {
		name    string
		payload Payload
		want    string
	}{
		{
			name:    "with http prefix",
			payload: Payload{URL: "http://abc123.oast.fun"},
			want:    "http://abc123.oast.fun",
		},
		{
			name:    "without prefix",
			payload: Payload{URL: "abc123.oast.fun"},
			want:    "http://abc123.oast.fun",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.payload.HTTPPayload()
			if got != tt.want {
				t.Errorf("HTTPPayload() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInteraction_String(t *testing.T) {
	interaction := &Interaction{
		Protocol:    "dns",
		FullID:      "abc123.oast.example.com",
		RemoteAddr:  "1.2.3.4",
		Timestamp:   time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		PayloadType: "sqli",
	}

	str := interaction.String()
	if str == "" {
		t.Error("String() should not be empty")
	}
	if len(str) < 10 {
		t.Error("String() should contain meaningful content")
	}
}

func TestPayloadTypes(t *testing.T) {
	types := map[string]string{
		"sqli": PayloadTypeSQLi,
		"xxe":  PayloadTypeXXE,
		"ssrf": PayloadTypeSSRF,
		"lfi":  PayloadTypeLFI,
		"rce":  PayloadTypeRCE,
		"ssti": PayloadTypeSSTI,
	}

	for name, pt := range types {
		if pt == "" {
			t.Errorf("PayloadType %s should not be empty", name)
		}
		if pt != name {
			t.Errorf("PayloadType %s = %q, want %q", name, pt, name)
		}
	}
}

func TestExtractID(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"http://abc123.oast.fun", "abc123"},
		{"https://xyz789.interact.sh", "xyz789"},
		{"test.oast.fun", "test"},
	}

	for _, tt := range tests {
		got := extractID(tt.url)
		if got != tt.want {
			t.Errorf("extractID(%q) = %q, want %q", tt.url, got, tt.want)
		}
	}
}

// TestNewClient_Integration is an integration test that requires network access.
// It is skipped by default and should be run manually when needed.
func TestNewClient_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client, err := NewClient()
	if err != nil {
		t.Skipf("Skipping - interactsh unavailable: %v", err)
	}
	defer client.Close()

	// Generate a payload
	payload := client.GeneratePayload(PayloadTypeSQLi)
	if payload.URL == "" {
		t.Error("Payload URL should not be empty")
	}

	t.Logf("Generated payload URL: %s", payload.URL)
}

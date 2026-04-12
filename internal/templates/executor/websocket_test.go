package executor

import (
	"testing"
	"time"
)

func TestNewWebSocketExecutor(t *testing.T) {
	t.Run("nil config uses defaults", func(t *testing.T) {
		exec := NewWebSocketExecutor(nil)
		if exec == nil {
			t.Fatal("NewWebSocketExecutor(nil) returned nil")
		}
		if exec.matcherEngine == nil {
			t.Error("matcherEngine not initialised")
		}
		if exec.config == nil {
			t.Fatal("config should not be nil")
		}
		if exec.config.Timeout != 10*time.Second {
			t.Errorf("default Timeout = %v, want 10s", exec.config.Timeout)
		}
	})

	t.Run("custom config", func(t *testing.T) {
		cfg := &WebSocketConfig{Timeout: 5 * time.Second}
		exec := NewWebSocketExecutor(cfg)
		if exec.config.Timeout != 5*time.Second {
			t.Errorf("Timeout = %v, want 5s", exec.config.Timeout)
		}
	})
}

func TestBuildWSURL(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		address string
		want    string
		wantErr bool
	}{
		{
			name:    "http to ws",
			target:  "http://example.com",
			address: "",
			want:    "ws://example.com",
		},
		{
			name:    "https to wss",
			target:  "https://example.com",
			address: "",
			want:    "wss://example.com",
		},
		{
			name:    "http with path to ws",
			target:  "http://example.com/chat",
			address: "",
			want:    "ws://example.com/chat",
		},
		{
			name:    "https with path to wss",
			target:  "https://example.com/ws",
			address: "",
			want:    "wss://example.com/ws",
		},
		{
			name:    "address overrides target",
			target:  "http://example.com",
			address: "https://ws.example.com/socket",
			want:    "wss://ws.example.com/socket",
		},
		{
			name:    "already ws scheme",
			target:  "ws://example.com",
			address: "",
			want:    "ws://example.com",
		},
		{
			name:    "already wss scheme",
			target:  "wss://example.com",
			address: "",
			want:    "wss://example.com",
		},
		{
			name:    "address already ws",
			target:  "http://example.com",
			address: "ws://example.com/feed",
			want:    "ws://example.com/feed",
		},
		{
			name:    "http with port",
			target:  "http://example.com:8080",
			address: "",
			want:    "ws://example.com:8080",
		},
		{
			name:    "https with port",
			target:  "https://example.com:8443",
			address: "",
			want:    "wss://example.com:8443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildWSURL(tt.target, tt.address)
			if (err != nil) != tt.wantErr {
				t.Errorf("buildWSURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("buildWSURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

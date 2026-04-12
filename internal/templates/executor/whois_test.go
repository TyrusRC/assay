package executor

import (
	"testing"
	"time"
)

func TestNewWHOISExecutor(t *testing.T) {
	t.Run("positive timeout", func(t *testing.T) {
		exec := NewWHOISExecutor(5*time.Second, "")
		if exec == nil {
			t.Fatal("NewWHOISExecutor() returned nil")
		}
		if exec.timeout != 5*time.Second {
			t.Errorf("timeout = %v, want 5s", exec.timeout)
		}
		if exec.matcherEngine == nil {
			t.Error("matcherEngine not initialised")
		}
	})

	t.Run("zero timeout uses default", func(t *testing.T) {
		exec := NewWHOISExecutor(0, "")
		if exec.timeout != 10*time.Second {
			t.Errorf("timeout = %v, want 10s (default)", exec.timeout)
		}
	})

	t.Run("negative timeout uses default", func(t *testing.T) {
		exec := NewWHOISExecutor(-1, "")
		if exec.timeout != 10*time.Second {
			t.Errorf("timeout = %v, want 10s (default)", exec.timeout)
		}
	})
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   string
	}{
		{
			name:   "plain http URL",
			target: "http://example.com",
			want:   "example.com",
		},
		{
			name:   "https URL",
			target: "https://example.com",
			want:   "example.com",
		},
		{
			name:   "URL with path",
			target: "https://example.com/some/path",
			want:   "example.com",
		},
		{
			name:   "URL with port",
			target: "https://example.com:8443",
			want:   "example.com",
		},
		{
			name:   "URL with port and path",
			target: "http://example.com:8080/api/v1",
			want:   "example.com",
		},
		{
			name:   "URL with query string",
			target: "https://example.com?foo=bar",
			want:   "example.com",
		},
		{
			name:   "URL with fragment",
			target: "https://example.com#section",
			want:   "example.com",
		},
		{
			name:   "bare hostname",
			target: "example.com",
			want:   "example.com",
		},
		{
			name:   "subdomain",
			target: "https://sub.example.com",
			want:   "sub.example.com",
		},
		{
			name:   "URL with credentials",
			target: "http://user:pass@example.com",
			want:   "example.com",
		},
		{
			name:   "empty string",
			target: "",
			want:   "",
		},
		{
			name:   "IP address",
			target: "http://192.168.1.1",
			want:   "192.168.1.1",
		},
		{
			name:   "IP address with port",
			target: "http://192.168.1.1:80",
			want:   "192.168.1.1",
		},
	}

	exec := NewWHOISExecutor(0, "")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := exec.extractDomain(tt.target)
			if got != tt.want {
				t.Errorf("extractDomain(%q) = %q, want %q", tt.target, got, tt.want)
			}
		})
	}
}

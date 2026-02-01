package executor

import (
	"testing"
)

func TestBuildURL(t *testing.T) {
	exec := New(nil)

	tests := []struct {
		base     string
		path     string
		expected string
	}{
		{"http://example.com", "/test", "http://example.com/test"},
		{"http://example.com/", "/test", "http://example.com/test"},
		{"http://example.com", "{{BaseURL}}/test", "http://example.com/test"},
		{"https://example.com:8080", "/api/v1", "https://example.com:8080/api/v1"},
	}

	for _, tt := range tests {
		result := exec.buildURL(tt.base, tt.path)
		if result != tt.expected {
			t.Errorf("buildURL(%q, %q) = %q, want %q", tt.base, tt.path, result, tt.expected)
		}
	}
}

func TestInterpolate(t *testing.T) {
	exec := New(nil)

	vars := map[string]interface{}{
		"Host":   "example.com",
		"Port":   8080,
		"Scheme": "https",
	}

	tests := []struct {
		input    string
		expected string
	}{
		{"{{Host}}", "example.com"},
		{"{{Scheme}}://{{Host}}:{{Port}}", "https://example.com:8080"},
		{"no vars here", "no vars here"},
	}

	for _, tt := range tests {
		result := exec.interpolate(tt.input, vars)
		if result != tt.expected {
			t.Errorf("interpolate(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestParseRawRequest(t *testing.T) {
	raw := `GET /api/users HTTP/1.1
Host: example.com
Accept: application/json

{"query": "test"}`

	method, path, body, headers := parseRawRequest(raw)

	if method != "GET" {
		t.Errorf("method = %q, want GET", method)
	}
	if path != "/api/users" {
		t.Errorf("path = %q, want /api/users", path)
	}
	if headers["Host"] != "example.com" {
		t.Errorf("Host header = %q, want example.com", headers["Host"])
	}
	if body != `{"query": "test"}` {
		t.Errorf("body = %q, want {\"query\": \"test\"}", body)
	}
}

func TestApplyFuzzType(t *testing.T) {
	tests := []struct {
		original string
		payload  string
		fuzzType string
		expected string
	}{
		{"value", "payload", "replace", "payload"},
		{"value", "pre-", "prefix", "pre-value"},
		{"value", "-post", "postfix", "value-post"},
		{"value", "default", "", "default"},
	}

	for _, tt := range tests {
		result := applyFuzzType(tt.original, tt.payload, tt.fuzzType)
		if result != tt.expected {
			t.Errorf("applyFuzzType(%q, %q, %q) = %q, want %q",
				tt.original, tt.payload, tt.fuzzType, result, tt.expected)
		}
	}
}

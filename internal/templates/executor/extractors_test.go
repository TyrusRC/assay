package executor

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestExtractRegex(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		content  string
		group    int
		expected []string
	}{
		{
			name:     "Simple match",
			patterns: []string{`version:\s+(\d+\.\d+)`},
			content:  "version: 1.5",
			group:    0,
			expected: []string{"1.5"},
		},
		{
			name:     "Multiple matches",
			patterns: []string{`id=(\d+)`},
			content:  "id=123 id=456 id=789",
			group:    1,
			expected: []string{"123", "456", "789"},
		},
		{
			name:     "Specific group",
			patterns: []string{`(foo)(bar)`},
			content:  "foobar",
			group:    2,
			expected: []string{"bar"},
		},
		{
			name:     "No match",
			patterns: []string{`xyz\d+`},
			content:  "abc123",
			group:    0,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractRegex(tt.patterns, tt.content, tt.group)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("extractRegex() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestExtractKVal(t *testing.T) {
	headers := map[string]string{
		"Content-Type": "application/json",
		"X-Version":    "1.0.0",
		"Server":       "nginx",
	}

	tests := []struct {
		name     string
		keys     []string
		expected []string
	}{
		{
			name:     "Exact match",
			keys:     []string{"Content-Type"},
			expected: []string{"application/json"},
		},
		{
			name:     "Case insensitive",
			keys:     []string{"content-type"},
			expected: []string{"application/json"},
		},
		{
			name:     "Multiple keys",
			keys:     []string{"Server", "X-Version"},
			expected: []string{"nginx", "1.0.0"},
		},
		{
			name:     "Missing key",
			keys:     []string{"X-Missing"},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractKVal(tt.keys, headers)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("extractKVal() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestExtractJSON(t *testing.T) {
	tests := []struct {
		name     string
		paths    []string
		content  string
		expected []string
	}{
		{
			name:     "Simple path",
			paths:    []string{"name"},
			content:  `{"name": "test"}`,
			expected: []string{"test"},
		},
		{
			name:     "Nested path",
			paths:    []string{"user.name"},
			content:  `{"user": {"name": "john"}}`,
			expected: []string{"john"},
		},
		{
			name:     "Number value",
			paths:    []string{"id"},
			content:  `{"id": 123}`,
			expected: []string{"123"},
		},
		{
			name:     "Boolean value",
			paths:    []string{"active"},
			content:  `{"active": true}`,
			expected: []string{"true"},
		},
		{
			name:     "Missing path",
			paths:    []string{"missing"},
			content:  `{"name": "test"}`,
			expected: nil,
		},
		{
			name:     "Invalid JSON",
			paths:    []string{"name"},
			content:  `not json`,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractJSON(tt.paths, tt.content)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("extractJSON() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestExtractXPath(t *testing.T) {
	tests := []struct {
		name     string
		paths    []string
		content  string
		expected []string
	}{
		{
			name:     "Simple tag",
			paths:    []string{"//title"},
			content:  `<html><title>Test Page</title></html>`,
			expected: []string{"Test Page"},
		},
		{
			name:     "Nested path",
			paths:    []string{"/root/item"},
			content:  `<root><item>Value1</item><item>Value2</item></root>`,
			expected: []string{"Value1", "Value2"},
		},
		{
			name:     "No match",
			paths:    []string{"//missing"},
			content:  `<root><item>test</item></root>`,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractXPath(tt.paths, tt.content)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("extractXPath() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestExtractJSONPath_ComplexTypes(t *testing.T) {
	content := `{
		"string": "hello",
		"number": 42,
		"float": 3.14,
		"bool": true,
		"null": null,
		"array": [1, 2, 3],
		"object": {"key": "value"}
	}`

	var data interface{}
	if err := json.Unmarshal([]byte(content), &data); err != nil {
		t.Fatalf("Failed to parse test JSON: %v", err)
	}

	tests := []struct {
		path     string
		expected string
	}{
		{"string", "hello"},
		{"number", "42"},
		{"float", "3.14"},
		{"bool", "true"},
		{"null", "null"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := extractJSONPath(data, tt.path)
			if result != tt.expected {
				t.Errorf("extractJSONPath(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

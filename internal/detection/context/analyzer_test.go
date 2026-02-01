package context

import (
	"testing"
)

func TestAnalyzer_AnalyzeParameter(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		name     string
		param    string
		value    string
		expected ParameterType
	}{
		{
			name:     "numeric ID",
			param:    "id",
			value:    "123",
			expected: TypeNumeric,
		},
		{
			name:     "negative number",
			param:    "offset",
			value:    "-10",
			expected: TypeNumeric,
		},
		{
			name:     "float number",
			param:    "price",
			value:    "19.99",
			expected: TypeNumeric,
		},
		{
			name:     "string value",
			param:    "name",
			value:    "john",
			expected: TypeString,
		},
		{
			name:     "quoted string",
			param:    "search",
			value:    "\"hello world\"",
			expected: TypeString,
		},
		{
			name:     "boolean true",
			param:    "active",
			value:    "true",
			expected: TypeBoolean,
		},
		{
			name:     "boolean false",
			param:    "enabled",
			value:    "false",
			expected: TypeBoolean,
		},
		{
			name:     "boolean 1",
			param:    "flag",
			value:    "1",
			expected: TypeBoolean, // Single digit is ambiguous, check name
		},
		{
			name:     "email",
			param:    "email",
			value:    "user@example.com",
			expected: TypeEmail,
		},
		{
			name:     "URL",
			param:    "redirect",
			value:    "https://example.com/path",
			expected: TypeURL,
		},
		{
			name:     "file path",
			param:    "file",
			value:    "/etc/passwd",
			expected: TypePath,
		},
		{
			name:     "windows path",
			param:    "document",
			value:    "C:\\Users\\test\\file.txt",
			expected: TypePath,
		},
		{
			name:     "JSON object",
			param:    "data",
			value:    `{"key": "value"}`,
			expected: TypeJSON,
		},
		{
			name:     "JSON array",
			param:    "items",
			value:    `["a", "b", "c"]`,
			expected: TypeJSON,
		},
		{
			name:     "base64",
			param:    "token",
			value:    "SGVsbG8gV29ybGQ=",
			expected: TypeBase64,
		},
		{
			name:     "UUID",
			param:    "uuid",
			value:    "550e8400-e29b-41d4-a716-446655440000",
			expected: TypeUUID,
		},
		{
			name:     "date",
			param:    "date",
			value:    "2024-01-15",
			expected: TypeDate,
		},
		{
			name:     "empty value",
			param:    "empty",
			value:    "",
			expected: TypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.AnalyzeParameter(tt.param, tt.value)
			if result.Type != tt.expected {
				t.Errorf("AnalyzeParameter(%q, %q) = %v, want %v",
					tt.param, tt.value, result.Type, tt.expected)
			}
		})
	}
}

func TestAnalyzer_DetectReflection(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		name      string
		input     string
		response  string
		reflected bool
	}{
		{
			name:      "exact reflection",
			input:     "test123",
			response:  "Your search: test123",
			reflected: true,
		},
		{
			name:      "no reflection",
			input:     "test123",
			response:  "No results found",
			reflected: false,
		},
		{
			name:      "HTML encoded reflection",
			input:     "<script>",
			response:  "Input: &lt;script&gt;",
			reflected: true,
		},
		{
			name:      "URL encoded reflection",
			input:     "test value",
			response:  "Query: test%20value",
			reflected: true,
		},
		{
			name:      "case insensitive reflection",
			input:     "TestValue",
			response:  "Result: testvalue is found",
			reflected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.DetectReflection(tt.input, tt.response)
			if result.IsReflected != tt.reflected {
				t.Errorf("DetectReflection(%q, ...) = %v, want %v",
					tt.input, result.IsReflected, tt.reflected)
			}
		})
	}
}

func TestAnalyzer_AnalyzeResponseContext(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		name     string
		input    string
		response string
		context  ReflectionContext
	}{
		{
			name:     "HTML body context",
			input:    "test",
			response: "<html><body>test</body></html>",
			context:  ContextHTMLBody,
		},
		{
			name:     "HTML attribute context",
			input:    "test",
			response: `<input value="test">`,
			context:  ContextHTMLAttribute,
		},
		{
			name:     "JavaScript context",
			input:    "test",
			response: `<script>var x = "test";</script>`,
			context:  ContextJavaScript,
		},
		{
			name:     "URL context",
			input:    "test",
			response: `<a href="/path?q=test">Link</a>`,
			context:  ContextURL,
		},
		{
			name:     "CSS context",
			input:    "test",
			response: `<style>body { background: test; }</style>`,
			context:  ContextCSS,
		},
		{
			name:     "JSON context",
			input:    "test",
			response: `{"message": "test"}`,
			context:  ContextJSON,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.AnalyzeResponseContext(tt.input, tt.response)
			if result.Context != tt.context {
				t.Errorf("AnalyzeResponseContext() context = %v, want %v",
					result.Context, tt.context)
			}
		})
	}
}

func TestParameterType_String(t *testing.T) {
	tests := []struct {
		ptype ParameterType
		want  string
	}{
		{TypeString, "string"},
		{TypeNumeric, "numeric"},
		{TypeBoolean, "boolean"},
		{TypeEmail, "email"},
		{TypeURL, "url"},
		{TypePath, "path"},
		{TypeJSON, "json"},
		{TypeBase64, "base64"},
		{TypeUUID, "uuid"},
		{TypeDate, "date"},
		{TypeUnknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if tt.ptype.String() != tt.want {
				t.Errorf("String() = %q, want %q", tt.ptype.String(), tt.want)
			}
		})
	}
}

func TestReflectionContext_String(t *testing.T) {
	tests := []struct {
		ctx  ReflectionContext
		want string
	}{
		{ContextHTMLBody, "html_body"},
		{ContextHTMLAttribute, "html_attribute"},
		{ContextJavaScript, "javascript"},
		{ContextURL, "url"},
		{ContextCSS, "css"},
		{ContextJSON, "json"},
		{ContextNone, "none"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if tt.ctx.String() != tt.want {
				t.Errorf("String() = %q, want %q", tt.ctx.String(), tt.want)
			}
		})
	}
}

func TestAnalysisResult_Fields(t *testing.T) {
	result := &AnalysisResult{
		Type:       TypeString,
		Confidence: 0.95,
		Patterns:   []string{"alphanumeric"},
	}

	if result.Type != TypeString {
		t.Errorf("Type = %v, want %v", result.Type, TypeString)
	}
	if result.Confidence != 0.95 {
		t.Errorf("Confidence = %f, want %f", result.Confidence, 0.95)
	}
	if len(result.Patterns) != 1 {
		t.Errorf("Patterns length = %d, want 1", len(result.Patterns))
	}
}

func TestReflectionResult_Fields(t *testing.T) {
	result := &ReflectionResult{
		IsReflected: true,
		Encoding:    "html",
		Context:     ContextHTMLBody,
	}

	if !result.IsReflected {
		t.Error("IsReflected should be true")
	}
	if result.Encoding != "html" {
		t.Errorf("Encoding = %q, want %q", result.Encoding, "html")
	}
}

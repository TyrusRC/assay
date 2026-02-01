package matchers

import (
	"testing"
)

func TestDSLEngine_StringFunctions(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{
		"body": "Hello World",
		"url":  "https://example.com/path",
	}

	tests := []struct {
		name        string
		expr        string
		expectMatch bool
	}{
		// startsWith
		{
			name:        "startsWith - match",
			expr:        `startsWith(body, "Hello")`,
			expectMatch: true,
		},
		{
			name:        "startsWith - no match",
			expr:        `startsWith(body, "World")`,
			expectMatch: false,
		},
		// endsWith
		{
			name:        "endsWith - match",
			expr:        `endsWith(body, "World")`,
			expectMatch: true,
		},
		{
			name:        "endsWith - no match",
			expr:        `endsWith(body, "Hello")`,
			expectMatch: false,
		},
		// toUpper
		{
			name:        "toUpper equality",
			expr:        `toUpper(body) == "HELLO WORLD"`,
			expectMatch: true,
		},
		// toLower
		{
			name:        "toLower equality",
			expr:        `toLower(body) == "hello world"`,
			expectMatch: true,
		},
		// trim
		{
			name:        "trim",
			expr:        `trim("  test  ") == "test"`,
			expectMatch: true,
		},
		// replace
		{
			name:        "replace",
			expr:        `replace(body, "World", "Universe") == "Hello Universe"`,
			expectMatch: true,
		},
		// contains (existing)
		{
			name:        "contains - match",
			expr:        `contains(body, "llo Wor")`,
			expectMatch: true,
		},
		// split and join
		{
			name:        "split and index",
			expr:        `split(url, "/")[2] == "example.com"`,
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dsl.Evaluate(tt.expr, ctx)
			if result != tt.expectMatch {
				t.Errorf("Evaluate(%q) = %v, want %v", tt.expr, result, tt.expectMatch)
			}
		})
	}
}

func TestDSLEngine_EncodingFunctions(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{
		"payload": "test payload",
	}

	tests := []struct {
		name        string
		expr        string
		expectMatch bool
	}{
		// base64Encode/Decode
		{
			name:        "base64Encode",
			expr:        `base64Encode("hello") == "aGVsbG8="`,
			expectMatch: true,
		},
		{
			name:        "base64Decode",
			expr:        `base64Decode("aGVsbG8=") == "hello"`,
			expectMatch: true,
		},
		{
			name:        "base64 roundtrip",
			expr:        `base64Decode(base64Encode(payload)) == payload`,
			expectMatch: true,
		},
		// urlEncode/Decode
		{
			name:        "urlEncode",
			expr:        `urlEncode("hello world") == "hello+world" || urlEncode("hello world") == "hello%20world"`,
			expectMatch: true,
		},
		{
			name:        "urlDecode",
			expr:        `urlDecode("hello%20world") == "hello world"`,
			expectMatch: true,
		},
		// htmlEncode/Decode
		{
			name:        "htmlEncode",
			expr:        `htmlEncode("<script>") == "&lt;script&gt;"`,
			expectMatch: true,
		},
		{
			name:        "htmlDecode",
			expr:        `htmlDecode("&lt;script&gt;") == "<script>"`,
			expectMatch: true,
		},
		{
			name:        "htmlEncode quotes",
			expr:        `contains(htmlEncode("\"test\""), "&quot;") || contains(htmlEncode("\"test\""), "&#34;")`,
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dsl.Evaluate(tt.expr, ctx)
			if result != tt.expectMatch {
				t.Errorf("Evaluate(%q) = %v, want %v", tt.expr, result, tt.expectMatch)
			}
		})
	}
}

func TestDSLEngine_HashFunctions(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{}

	tests := []struct {
		name        string
		expr        string
		expectMatch bool
	}{
		// md5
		{
			name:        "md5 hash",
			expr:        `md5("hello") == "5d41402abc4b2a76b9719d911017c592"`,
			expectMatch: true,
		},
		// sha1
		{
			name:        "sha1 hash",
			expr:        `sha1("hello") == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"`,
			expectMatch: true,
		},
		// sha256
		{
			name:        "sha256 hash",
			expr:        `sha256("hello") == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"`,
			expectMatch: true,
		},
		// hash empty string
		{
			name:        "md5 empty",
			expr:        `md5("") == "d41d8cd98f00b204e9800998ecf8427e"`,
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dsl.Evaluate(tt.expr, ctx)
			if result != tt.expectMatch {
				t.Errorf("Evaluate(%q) = %v, want %v", tt.expr, result, tt.expectMatch)
			}
		})
	}
}

func TestDSLEngine_ListFunctions(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{
		"items": []string{"apple", "banana", "cherry"},
		"nums":  []int{1, 2, 3, 4, 5},
	}

	tests := []struct {
		name        string
		expr        string
		expectMatch bool
	}{
		// contains for list
		{
			name:        "contains list - match",
			expr:        `contains(items, "banana")`,
			expectMatch: true,
		},
		{
			name:        "contains list - no match",
			expr:        `contains(items, "grape")`,
			expectMatch: false,
		},
		// join
		{
			name:        "join list",
			expr:        `join(items, ",") == "apple,banana,cherry"`,
			expectMatch: true,
		},
		{
			name:        "join with space",
			expr:        `join(items, " ") == "apple banana cherry"`,
			expectMatch: true,
		},
		// len
		{
			name:        "len of list",
			expr:        `len(items) == 3`,
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dsl.Evaluate(tt.expr, ctx)
			if result != tt.expectMatch {
				t.Errorf("Evaluate(%q) = %v, want %v", tt.expr, result, tt.expectMatch)
			}
		})
	}
}

func TestDSLEngine_ComparisonOperators(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{
		"status_code":    200,
		"content_length": 1024,
		"body":           "test content",
	}

	tests := []struct {
		name        string
		expr        string
		expectMatch bool
	}{
		{
			name:        "equal int",
			expr:        `status_code == 200`,
			expectMatch: true,
		},
		{
			name:        "not equal",
			expr:        `status_code != 404`,
			expectMatch: true,
		},
		{
			name:        "greater than",
			expr:        `content_length > 500`,
			expectMatch: true,
		},
		{
			name:        "less than",
			expr:        `content_length < 2000`,
			expectMatch: true,
		},
		{
			name:        "greater than or equal",
			expr:        `content_length >= 1024`,
			expectMatch: true,
		},
		{
			name:        "less than or equal",
			expr:        `content_length <= 1024`,
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dsl.Evaluate(tt.expr, ctx)
			if result != tt.expectMatch {
				t.Errorf("Evaluate(%q) = %v, want %v", tt.expr, result, tt.expectMatch)
			}
		})
	}
}

func TestDSLEngine_LogicalOperators(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{
		"status_code": 200,
		"body":        "success",
	}

	tests := []struct {
		name        string
		expr        string
		expectMatch bool
	}{
		{
			name:        "AND - both true",
			expr:        `status_code == 200 && contains(body, "success")`,
			expectMatch: true,
		},
		{
			name:        "AND - one false",
			expr:        `status_code == 200 && contains(body, "error")`,
			expectMatch: false,
		},
		{
			name:        "OR - one true",
			expr:        `status_code == 404 || contains(body, "success")`,
			expectMatch: true,
		},
		{
			name:        "OR - both false",
			expr:        `status_code == 404 || contains(body, "error")`,
			expectMatch: false,
		},
		{
			name:        "NOT",
			expr:        `!contains(body, "error")`,
			expectMatch: true,
		},
		{
			name:        "Complex expression",
			expr:        `(status_code == 200 || status_code == 201) && !contains(body, "error")`,
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dsl.Evaluate(tt.expr, ctx)
			if result != tt.expectMatch {
				t.Errorf("Evaluate(%q) = %v, want %v", tt.expr, result, tt.expectMatch)
			}
		})
	}
}

func TestDSLEngine_RegexMatch(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{
		"body": "Version: 2.5.1-beta",
	}

	tests := []struct {
		name        string
		expr        string
		expectMatch bool
	}{
		{
			name:        "regex match version",
			expr:        `regex_match(body, "[0-9]+\.[0-9]+\.[0-9]+")`,
			expectMatch: true,
		},
		{
			name:        "regex no match",
			expr:        `regex_match(body, "^Error:")`,
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dsl.Evaluate(tt.expr, ctx)
			if result != tt.expectMatch {
				t.Errorf("Evaluate(%q) = %v, want %v", tt.expr, result, tt.expectMatch)
			}
		})
	}
}

func TestDSLEngine_NestedFunctions(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{
		"data": "  HELLO  ",
	}

	tests := []struct {
		name        string
		expr        string
		expectMatch bool
	}{
		{
			name:        "trim and toLower",
			expr:        `toLower(trim(data)) == "hello"`,
			expectMatch: true,
		},
		{
			name:        "nested encode/decode",
			expr:        `base64Decode(base64Encode("test")) == "test"`,
			expectMatch: true,
		},
		{
			name:        "len of trimmed",
			expr:        `len(trim(data)) == 5`,
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dsl.Evaluate(tt.expr, ctx)
			if result != tt.expectMatch {
				t.Errorf("Evaluate(%q) = %v, want %v", tt.expr, result, tt.expectMatch)
			}
		})
	}
}

func TestDSLEngine_InvalidExpressions(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{}

	invalidExprs := []string{
		`unknownFunction()`,
		`((())`,
	}

	for _, expr := range invalidExprs {
		t.Run(expr, func(t *testing.T) {
			result := dsl.Evaluate(expr, ctx)
			if result {
				t.Errorf("Invalid expression %q should return false", expr)
			}
		})
	}
}

func TestNewDSLEngine(t *testing.T) {
	dsl := NewDSLEngine()
	if dsl == nil {
		t.Fatal("NewDSLEngine() returned nil")
	}
}

func TestDSLEngine_EvaluateString(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{
		"test": "value",
	}

	// Test that EvaluateString returns string result
	result := dsl.EvaluateString(`toUpper("hello")`, ctx)
	if result != "HELLO" {
		t.Errorf("EvaluateString() = %q, want HELLO", result)
	}

	result = dsl.EvaluateString(`md5("test")`, ctx)
	if result != "098f6bcd4621d373cade4e832627b4f6" {
		t.Errorf("EvaluateString() = %q, want md5 hash", result)
	}
}

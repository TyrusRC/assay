package matchers

import (
	"testing"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/templates"
)

func TestNew(t *testing.T) {
	e := New()
	if e == nil {
		t.Fatal("New() returned nil")
	}
	if e.regexCache == nil {
		t.Error("regexCache not initialized")
	}
}

func TestMatch_Word(t *testing.T) {
	e := New()
	resp := &Response{
		Body: "Welcome to Apache Tomcat Server",
	}

	tests := []struct {
		name        string
		matcher     *templates.Matcher
		expectMatch bool
	}{
		{
			name: "Single word match",
			matcher: &templates.Matcher{
				Type:  "word",
				Part:  "body",
				Words: []string{"Apache"},
			},
			expectMatch: true,
		},
		{
			name: "Multiple words OR",
			matcher: &templates.Matcher{
				Type:      "word",
				Part:      "body",
				Words:     []string{"nginx", "Apache"},
				Condition: "or",
			},
			expectMatch: true,
		},
		{
			name: "Multiple words AND",
			matcher: &templates.Matcher{
				Type:      "word",
				Part:      "body",
				Words:     []string{"Apache", "Tomcat"},
				Condition: "and",
			},
			expectMatch: true,
		},
		{
			name: "No match",
			matcher: &templates.Matcher{
				Type:  "word",
				Part:  "body",
				Words: []string{"nginx"},
			},
			expectMatch: false,
		},
		{
			name: "Case insensitive",
			matcher: &templates.Matcher{
				Type:            "word",
				Part:            "body",
				Words:           []string{"apache"},
				CaseInsensitive: true,
			},
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := e.Match(tt.matcher, resp, nil)
			if result.Matched != tt.expectMatch {
				t.Errorf("Match() = %v, want %v", result.Matched, tt.expectMatch)
			}
		})
	}
}

func TestMatch_Regex(t *testing.T) {
	e := New()
	resp := &Response{
		Body: "Version: 2.5.1",
	}

	tests := []struct {
		name          string
		matcher       *templates.Matcher
		expectMatch   bool
		expectExtract []string
	}{
		{
			name: "Simple regex",
			matcher: &templates.Matcher{
				Type:  "regex",
				Part:  "body",
				Regex: []string{`Version:\s+\d+\.\d+\.\d+`},
			},
			expectMatch: true,
		},
		{
			name: "Regex with group",
			matcher: &templates.Matcher{
				Type:  "regex",
				Part:  "body",
				Regex: []string{`Version:\s+(\d+\.\d+\.\d+)`},
			},
			expectMatch:   true,
			expectExtract: []string{"2.5.1"},
		},
		{
			name: "No match",
			matcher: &templates.Matcher{
				Type:  "regex",
				Part:  "body",
				Regex: []string{`nginx/\d+`},
			},
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := e.Match(tt.matcher, resp, nil)
			if result.Matched != tt.expectMatch {
				t.Errorf("Match() = %v, want %v", result.Matched, tt.expectMatch)
			}
			if tt.expectExtract != nil {
				if len(result.Extracts) != len(tt.expectExtract) {
					t.Errorf("Extracts len = %d, want %d", len(result.Extracts), len(tt.expectExtract))
				}
			}
		})
	}
}

func TestMatch_Status(t *testing.T) {
	e := New()

	tests := []struct {
		name        string
		statusCode  int
		matcher     *templates.Matcher
		expectMatch bool
	}{
		{
			name:       "200 OK",
			statusCode: 200,
			matcher: &templates.Matcher{
				Type:   "status",
				Status: []int{200},
			},
			expectMatch: true,
		},
		{
			name:       "Multiple status codes",
			statusCode: 301,
			matcher: &templates.Matcher{
				Type:   "status",
				Status: []int{301, 302, 307},
			},
			expectMatch: true,
		},
		{
			name:       "No match",
			statusCode: 404,
			matcher: &templates.Matcher{
				Type:   "status",
				Status: []int{200, 201},
			},
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &Response{StatusCode: tt.statusCode}
			result := e.Match(tt.matcher, resp, nil)
			if result.Matched != tt.expectMatch {
				t.Errorf("Match() = %v, want %v", result.Matched, tt.expectMatch)
			}
		})
	}
}

func TestMatch_Size(t *testing.T) {
	e := New()

	tests := []struct {
		name          string
		contentLength int
		sizes         []int
		expectMatch   bool
	}{
		{"Exact match", 1024, []int{1024}, true},
		{"Multiple sizes", 512, []int{256, 512, 1024}, true},
		{"No match", 100, []int{200, 300}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &Response{ContentLength: tt.contentLength}
			matcher := &templates.Matcher{Type: "size", Size: tt.sizes}
			result := e.Match(matcher, resp, nil)
			if result.Matched != tt.expectMatch {
				t.Errorf("Match() = %v, want %v", result.Matched, tt.expectMatch)
			}
		})
	}
}

func TestMatch_Binary(t *testing.T) {
	e := New()
	resp := &Response{
		Body: string([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}), // PNG header
	}

	tests := []struct {
		name        string
		binary      []string
		expectMatch bool
	}{
		{"PNG header", []string{"89504E47"}, true},
		{"No match", []string{"FFD8FF"}, false}, // JPEG header
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := &templates.Matcher{Type: "binary", Binary: tt.binary}
			result := e.Match(matcher, resp, nil)
			if result.Matched != tt.expectMatch {
				t.Errorf("Match() = %v, want %v", result.Matched, tt.expectMatch)
			}
		})
	}
}

func TestMatch_DSL(t *testing.T) {
	e := New()
	resp := &Response{
		StatusCode:    200,
		ContentLength: 1000,
		Body:          "Hello World",
	}

	tests := []struct {
		name        string
		dsl         []string
		expectMatch bool
	}{
		{
			name:        "Status code check",
			dsl:         []string{"status_code == 200"},
			expectMatch: true,
		},
		{
			name:        "Contains check",
			dsl:         []string{`contains(body, "Hello")`},
			expectMatch: true,
		},
		{
			name:        "Body length check",
			dsl:         []string{"len(body) > 5"},
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := &templates.Matcher{Type: "dsl", DSL: tt.dsl}
			result := e.Match(matcher, resp, nil)
			if result.Matched != tt.expectMatch {
				t.Errorf("Match() = %v, want %v", result.Matched, tt.expectMatch)
			}
		})
	}
}

func TestMatchDSL_HeaderVariable(t *testing.T) {
	e := New()

	tests := []struct {
		name        string
		resp        *Response
		dsl         string
		expectMatch bool
	}{
		{
			name: "header variable contains header name",
			resp: &Response{
				StatusCode: 200,
				Body:       "hello",
				Headers: map[string]string{
					"X-Powered-By": "PHP/7.4",
				},
			},
			dsl:         `contains(header, "X-Powered-By")`,
			expectMatch: true,
		},
		{
			name: "all_headers alias works",
			resp: &Response{
				StatusCode: 200,
				Body:       "hello",
				Headers: map[string]string{
					"Content-Type": "text/html",
				},
			},
			dsl:         `contains(all_headers, "Content-Type")`,
			expectMatch: true,
		},
		{
			name: "header variable does not match missing header",
			resp: &Response{
				StatusCode: 200,
				Body:       "hello",
				Headers:    map[string]string{},
			},
			dsl:         `contains(header, "X-Powered-By")`,
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := &templates.Matcher{Type: "dsl", DSL: []string{tt.dsl}}
			result := e.Match(matcher, tt.resp, nil)
			if result.Matched != tt.expectMatch {
				t.Errorf("Match() = %v, want %v for DSL: %q", result.Matched, tt.expectMatch, tt.dsl)
			}
		})
	}
}

func TestMatchDSL_RawVariable(t *testing.T) {
	e := New()

	tests := []struct {
		name        string
		resp        *Response
		dsl         string
		expectMatch bool
	}{
		{
			name: "raw contains body content",
			resp: &Response{
				StatusCode: 200,
				Body:       "body content here",
				Headers: map[string]string{
					"Header-Name": "header-value",
				},
			},
			dsl:         `contains(raw, "body content")`,
			expectMatch: true,
		},
		{
			name: "raw contains header and body",
			resp: &Response{
				StatusCode: 200,
				Body:       "body content here",
				Headers: map[string]string{
					"Header-Name": "header-value",
				},
			},
			dsl:         `contains(raw, "body content") && contains(raw, "Header-Name")`,
			expectMatch: true,
		},
		{
			name: "raw does not contain missing content",
			resp: &Response{
				StatusCode: 200,
				Body:       "body content",
				Headers:    map[string]string{},
			},
			dsl:         `contains(raw, "missing-string")`,
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := &templates.Matcher{Type: "dsl", DSL: []string{tt.dsl}}
			result := e.Match(matcher, tt.resp, nil)
			if result.Matched != tt.expectMatch {
				t.Errorf("Match() = %v, want %v for DSL: %q", result.Matched, tt.expectMatch, tt.dsl)
			}
		})
	}
}

func TestMatchDSL_DurationVariable(t *testing.T) {
	e := New()

	tests := []struct {
		name        string
		duration    time.Duration
		dsl         string
		expectMatch bool
	}{
		{
			name:        "duration greater than 1 second",
			duration:    2 * time.Second,
			dsl:         "duration > 1",
			expectMatch: true,
		},
		{
			name:        "duration less than expected",
			duration:    500 * time.Millisecond,
			dsl:         "duration > 1",
			expectMatch: false,
		},
		{
			name:        "duration equals check",
			duration:    2 * time.Second,
			dsl:         "duration >= 2",
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &Response{
				StatusCode: 200,
				Body:       "response",
				Headers:    map[string]string{},
				Duration:   tt.duration,
			}
			matcher := &templates.Matcher{Type: "dsl", DSL: []string{tt.dsl}}
			result := e.Match(matcher, resp, nil)
			if result.Matched != tt.expectMatch {
				t.Errorf("Match() = %v, want %v for DSL: %q (duration=%v)", result.Matched, tt.expectMatch, tt.dsl, tt.duration)
			}
		})
	}
}

func TestMatch_Negative(t *testing.T) {
	e := New()
	resp := &Response{StatusCode: 200}

	matcher := &templates.Matcher{
		Type:     "status",
		Status:   []int{404},
		Negative: true,
	}

	result := e.Match(matcher, resp, nil)
	if !result.Matched {
		t.Error("Negative matcher should match when condition is false")
	}
}

func TestMatchAll_OR(t *testing.T) {
	e := New()
	resp := &Response{
		StatusCode: 200,
		Body:       "test",
	}

	matchers := []templates.Matcher{
		{Type: "status", Status: []int{404}},
		{Type: "word", Part: "body", Words: []string{"test"}},
	}

	matched, _ := e.MatchAll(matchers, "or", resp, nil)
	if !matched {
		t.Error("OR condition should match when any matcher matches")
	}
}

func TestMatchAll_AND(t *testing.T) {
	e := New()
	resp := &Response{
		StatusCode: 200,
		Body:       "test",
	}

	matchers := []templates.Matcher{
		{Type: "status", Status: []int{200}},
		{Type: "word", Part: "body", Words: []string{"test"}},
	}

	matched, _ := e.MatchAll(matchers, "and", resp, nil)
	if !matched {
		t.Error("AND condition should match when all matchers match")
	}

	// Test failure case
	matchers[0].Status = []int{404}
	matched, _ = e.MatchAll(matchers, "and", resp, nil)
	if matched {
		t.Error("AND condition should not match when any matcher fails")
	}
}

func TestMatchAll_Internal(t *testing.T) {
	e := New()
	resp := &Response{StatusCode: 200}

	matchers := []templates.Matcher{
		{Type: "status", Status: []int{200}, Internal: true},
	}

	matched, _ := e.MatchAll(matchers, "or", resp, nil)
	if matched {
		t.Error("Internal matchers should be skipped in final result")
	}
}

func TestGetMatchPart(t *testing.T) {
	e := New()
	resp := &Response{
		StatusCode:  200,
		Body:        "response body",
		ContentType: "text/html",
		Headers: map[string]string{
			"X-Test": "value",
		},
	}

	tests := []struct {
		part     string
		contains string
	}{
		{"body", "response body"},
		{"header", "X-Test"},
		{"status", "200"},
		{"content_type", "text/html"},
		{"all", "response body"},
		{"", "response body"},
	}

	for _, tt := range tests {
		result := e.getMatchPart(tt.part, resp)
		if len(result) == 0 {
			t.Errorf("getMatchPart(%q) returned empty", tt.part)
		}
	}
}

func TestHexDecode(t *testing.T) {
	tests := []struct {
		input    string
		expected []byte
		hasError bool
	}{
		{"48656C6C6F", []byte("Hello"), false},
		{"48 65 6C 6C 6F", []byte("Hello"), false},
		{"FF", []byte{0xFF}, false},
		{"GG", nil, true}, // Invalid hex
	}

	for _, tt := range tests {
		result, err := hexDecode(tt.input)
		if tt.hasError && err == nil {
			t.Errorf("hexDecode(%q) expected error", tt.input)
			continue
		}
		if !tt.hasError && err != nil {
			t.Errorf("hexDecode(%q) error: %v", tt.input, err)
			continue
		}
		if !tt.hasError && string(result) != string(tt.expected) {
			t.Errorf("hexDecode(%q) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestRegexCache(t *testing.T) {
	e := New()
	pattern := `test\d+`

	// First call should compile
	re1, err := e.getCompiledRegex(pattern, false)
	if err != nil {
		t.Fatalf("First compile failed: %v", err)
	}

	// Second call should use cache
	re2, err := e.getCompiledRegex(pattern, false)
	if err != nil {
		t.Fatalf("Second compile failed: %v", err)
	}

	if re1 != re2 {
		t.Error("Regex cache not working, got different regex objects")
	}

	// Case insensitive should be different
	re3, err := e.getCompiledRegex(pattern, true)
	if err != nil {
		t.Fatalf("Case insensitive compile failed: %v", err)
	}

	if re1 == re3 {
		t.Error("Case insensitive regex should be different")
	}
}

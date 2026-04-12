package analysis

import (
	"testing"

	skwshttp "github.com/swiss-knife-for-web-security/skws/internal/http"
)

func TestResponseSimilarity(t *testing.T) {
	tests := []struct {
		name    string
		a       string
		b       string
		wantMin float64
		wantMax float64
	}{
		{
			name:    "identical bodies return 1.0",
			a:       "the quick brown fox jumps over the lazy dog",
			b:       "the quick brown fox jumps over the lazy dog",
			wantMin: 1.0,
			wantMax: 1.0,
		},
		{
			name:    "completely different bodies return low score",
			a:       "alpha beta gamma delta",
			b:       "one two three four five six",
			wantMin: 0.0,
			wantMax: 0.1,
		},
		{
			name:    "partially overlapping bodies return medium score",
			a:       "the quick brown fox",
			b:       "the slow brown cat",
			wantMin: 0.3,
			wantMax: 0.7,
		},
		{
			name:    "empty body a returns 0.0",
			a:       "",
			b:       "some content here",
			wantMin: 0.0,
			wantMax: 0.0,
		},
		{
			name:    "empty body b returns 0.0",
			a:       "some content here",
			b:       "",
			wantMin: 0.0,
			wantMax: 0.0,
		},
		{
			name:    "both empty bodies return 1.0",
			a:       "",
			b:       "",
			wantMin: 1.0,
			wantMax: 1.0,
		},
		{
			name:    "single word identical",
			a:       "hello",
			b:       "hello",
			wantMin: 1.0,
			wantMax: 1.0,
		},
		{
			name:    "single word different",
			a:       "hello",
			b:       "world",
			wantMin: 0.0,
			wantMax: 0.0,
		},
		{
			name:    "html bodies with slight differences",
			a:       "<html><body><h1>Welcome</h1><p>Content here</p></body></html>",
			b:       "<html><body><h1>Welcome</h1><p>Different content</p></body></html>",
			wantMin: 0.3,
			wantMax: 0.9,
		},
		{
			name:    "whitespace only bodies are both empty after tokenization",
			a:       "   ",
			b:       "   ",
			wantMin: 1.0,
			wantMax: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResponseSimilarity(tt.a, tt.b)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("ResponseSimilarity() = %f, want [%f, %f]", got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestStripDynamicContent(t *testing.T) {
	tests := []struct {
		name  string
		input string
		check func(t *testing.T, result string)
	}{
		{
			name:  "strip UUID v4",
			input: `token: 550e8400-e29b-41d4-a716-446655440000 end`,
			check: func(t *testing.T, result string) {
				t.Helper()
				if result == `token: 550e8400-e29b-41d4-a716-446655440000 end` {
					t.Error("UUID was not stripped")
				}
			},
		},
		{
			name:  "strip Unix timestamp",
			input: `time: 1706745600 end`,
			check: func(t *testing.T, result string) {
				t.Helper()
				if result == `time: 1706745600 end` {
					t.Error("Unix timestamp was not stripped")
				}
			},
		},
		{
			name:  "strip ISO 8601 timestamp",
			input: `date: 2024-01-31T12:00:00Z end`,
			check: func(t *testing.T, result string) {
				t.Helper()
				if result == `date: 2024-01-31T12:00:00Z end` {
					t.Error("ISO 8601 timestamp was not stripped")
				}
			},
		},
		{
			name:  "strip CSRF token in hidden input",
			input: `<input type="hidden" name="csrf_token" value="abc123def456ghi789">`,
			check: func(t *testing.T, result string) {
				t.Helper()
				if result == `<input type="hidden" name="csrf_token" value="abc123def456ghi789">` {
					t.Error("CSRF token was not stripped")
				}
			},
		},
		{
			name:  "strip nonce attribute",
			input: `<script nonce="r4nd0mN0nc3V4lu3">alert(1)</script>`,
			check: func(t *testing.T, result string) {
				t.Helper()
				if result == `<script nonce="r4nd0mN0nc3V4lu3">alert(1)</script>` {
					t.Error("nonce value was not stripped")
				}
			},
		},
		{
			name:  "strip cache-busting query string",
			input: `<script src="/app.js?v=1706745600"></script>`,
			check: func(t *testing.T, result string) {
				t.Helper()
				if result == `<script src="/app.js?v=1706745600"></script>` {
					t.Error("cache-busting query string was not stripped")
				}
			},
		},
		{
			name:  "strip hex session ID",
			input: `session=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 path`,
			check: func(t *testing.T, result string) {
				t.Helper()
				if result == `session=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 path` {
					t.Error("hex session ID was not stripped")
				}
			},
		},
		{
			name:  "empty input returns empty",
			input: "",
			check: func(t *testing.T, result string) {
				t.Helper()
				if result != "" {
					t.Errorf("expected empty, got %q", result)
				}
			},
		},
		{
			name:  "static content is preserved",
			input: `<html><body><h1>Welcome</h1></body></html>`,
			check: func(t *testing.T, result string) {
				t.Helper()
				if result != `<html><body><h1>Welcome</h1></body></html>` {
					t.Errorf("static content changed: %q", result)
				}
			},
		},
		{
			name:  "bodies differing only in dynamic content become similar after stripping",
			input: `<html><p>Hello</p><input name="csrf" value="token123"><p>1706745600</p></html>`,
			check: func(t *testing.T, result string) {
				t.Helper()
				// Just verify something was stripped; the actual similarity
				// comparison is tested in the integration-style test below.
				if result == `<html><p>Hello</p><input name="csrf" value="token123"><p>1706745600</p></html>` {
					t.Error("expected some dynamic content to be stripped")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StripDynamicContent(tt.input)
			tt.check(t, result)
		})
	}
}

func TestStripDynamicContent_SimilarBodies(t *testing.T) {
	bodyA := `<html><body>
		<h1>Dashboard</h1>
		<input type="hidden" name="csrf_token" value="tokenAAA111">
		<p>Updated: 2024-01-31T12:00:00Z</p>
		<p>Session: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6</p>
		<script nonce="nonceA123">init()</script>
	</body></html>`

	bodyB := `<html><body>
		<h1>Dashboard</h1>
		<input type="hidden" name="csrf_token" value="tokenBBB222">
		<p>Updated: 2024-02-01T08:30:00Z</p>
		<p>Session: f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6</p>
		<script nonce="nonceB456">init()</script>
	</body></html>`

	strippedA := StripDynamicContent(bodyA)
	strippedB := StripDynamicContent(bodyB)

	similarity := ResponseSimilarity(strippedA, strippedB)
	if similarity < 0.8 {
		t.Errorf("Bodies differing only in dynamic content should be similar after stripping, got %f", similarity)
	}
}

func TestIsSameResponse(t *testing.T) {
	tests := []struct {
		name      string
		a         *skwshttp.Response
		b         *skwshttp.Response
		threshold float64
		want      bool
	}{
		{
			name: "identical responses are same",
			a: &skwshttp.Response{
				StatusCode: 200,
				Body:       "the quick brown fox jumps over the lazy dog",
			},
			b: &skwshttp.Response{
				StatusCode: 200,
				Body:       "the quick brown fox jumps over the lazy dog",
			},
			threshold: 0.9,
			want:      true,
		},
		{
			name: "different status codes are not same",
			a: &skwshttp.Response{
				StatusCode: 200,
				Body:       "the quick brown fox jumps over the lazy dog",
			},
			b: &skwshttp.Response{
				StatusCode: 500,
				Body:       "the quick brown fox jumps over the lazy dog",
			},
			threshold: 0.9,
			want:      false,
		},
		{
			name: "completely different bodies are not same",
			a: &skwshttp.Response{
				StatusCode: 200,
				Body:       "alpha beta gamma delta",
			},
			b: &skwshttp.Response{
				StatusCode: 200,
				Body:       "one two three four five six",
			},
			threshold: 0.9,
			want:      false,
		},
		{
			name: "bodies differing only in dynamic content are same",
			a: &skwshttp.Response{
				StatusCode: 200,
				Body:       `<p>Hello</p><input name="csrf" value="550e8400-e29b-41d4-a716-446655440000">`,
			},
			b: &skwshttp.Response{
				StatusCode: 200,
				Body:       `<p>Hello</p><input name="csrf" value="660e8400-e29b-41d4-a716-557766550000">`,
			},
			threshold: 0.8,
			want:      true,
		},
		{
			name: "nil response a returns false",
			a:    nil,
			b: &skwshttp.Response{
				StatusCode: 200,
				Body:       "content",
			},
			threshold: 0.9,
			want:      false,
		},
		{
			name: "nil response b returns false",
			a: &skwshttp.Response{
				StatusCode: 200,
				Body:       "content",
			},
			b:         nil,
			threshold: 0.9,
			want:      false,
		},
		{
			name:      "both nil responses return false",
			a:         nil,
			b:         nil,
			threshold: 0.9,
			want:      false,
		},
		{
			name: "low threshold makes different bodies match",
			a: &skwshttp.Response{
				StatusCode: 200,
				Body:       "hello world foo bar",
			},
			b: &skwshttp.Response{
				StatusCode: 200,
				Body:       "hello world baz qux",
			},
			threshold: 0.2,
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSameResponse(tt.a, tt.b, tt.threshold)
			if got != tt.want {
				t.Errorf("IsSameResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

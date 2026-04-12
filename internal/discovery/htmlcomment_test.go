package discovery

import (
	"context"
	"testing"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

func TestHTMLCommentDiscoverer_Name(t *testing.T) {
	d := NewHTMLCommentDiscoverer()
	if d.Name() != "htmlcomment" {
		t.Errorf("Name() = %q, want %q", d.Name(), "htmlcomment")
	}
}

func TestHTMLCommentDiscoverer_Discover(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		expectedParams []core.Parameter
		expectEmpty    bool
	}{
		{
			name: "key=value patterns in comments",
			body: `<html>
				<!-- debug=true -->
				<!-- token=abc123 -->
				<body>Hello</body>
			</html>`,
			expectedParams: []core.Parameter{
				{Name: "debug", Location: core.ParamLocationQuery, Value: "true"},
				{Name: "token", Location: core.ParamLocationQuery, Value: "abc123"},
			},
		},
		{
			name: "URL with query string in comment",
			body: `<html>
				<!-- old endpoint: /api/search?q=test&page=1 -->
				<body>Hello</body>
			</html>`,
			expectedParams: []core.Parameter{
				{Name: "q", Location: core.ParamLocationQuery, Value: "test"},
				{Name: "page", Location: core.ParamLocationQuery, Value: "1"},
			},
		},
		{
			name: "TODO with parameter mention",
			body: `<html>
				<!-- TODO: add validation for user_id parameter -->
				<!-- FIXME: sanitize the redirect param -->
				<body>Hello</body>
			</html>`,
			expectedParams: []core.Parameter{
				{Name: "user_id", Location: core.ParamLocationQuery},
				{Name: "redirect", Location: core.ParamLocationQuery},
			},
		},
		{
			name: "multiple patterns in single comment",
			body: `<html>
				<!-- config: admin=true role=superuser -->
				<body>Hello</body>
			</html>`,
			expectedParams: []core.Parameter{
				{Name: "admin", Location: core.ParamLocationQuery, Value: "true"},
				{Name: "role", Location: core.ParamLocationQuery, Value: "superuser"},
			},
		},
		{
			name:        "no comments",
			body:        `<html><body>No comments here</body></html>`,
			expectEmpty: true,
		},
		{
			name:        "empty body",
			body:        "",
			expectEmpty: true,
		},
		{
			name:        "comment without parameters",
			body:        `<html><!-- This is just a regular comment --><body></body></html>`,
			expectEmpty: true,
		},
		{
			name: "deduplicates parameters",
			body: `<html>
				<!-- debug=true -->
				<!-- debug=false -->
				<body></body>
			</html>`,
			expectedParams: []core.Parameter{
				{Name: "debug", Location: core.ParamLocationQuery},
			},
		},
	}

	d := NewHTMLCommentDiscoverer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{Body: tt.body}
			params, err := d.Discover(context.Background(), "http://example.com", resp)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}

			if tt.expectEmpty {
				if len(params) != 0 {
					t.Errorf("Discover() should return empty, got %v", params)
				}
				return
			}

			if len(params) != len(tt.expectedParams) {
				t.Fatalf("Discover() count = %d, want %d; got %v", len(params), len(tt.expectedParams), params)
			}

			for _, expected := range tt.expectedParams {
				found := false
				for _, p := range params {
					if p.Name == expected.Name && p.Location == expected.Location {
						found = true
						if expected.Value != "" && p.Value != expected.Value {
							t.Errorf("param %q value = %q, want %q", expected.Name, p.Value, expected.Value)
						}
						break
					}
				}
				if !found {
					t.Errorf("missing expected param: Name=%q Location=%q", expected.Name, expected.Location)
				}
			}
		})
	}
}

func TestHTMLCommentDiscoverer_NilResponse(t *testing.T) {
	d := NewHTMLCommentDiscoverer()
	params, err := d.Discover(context.Background(), "http://example.com", nil)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if params != nil {
		t.Errorf("Discover() with nil response = %v, want nil", params)
	}
}

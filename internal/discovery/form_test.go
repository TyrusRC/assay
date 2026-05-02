package discovery

import (
	"context"
	"testing"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

func TestFormDiscoverer_Name(t *testing.T) {
	d := NewFormDiscoverer()
	if d.Name() != "form" {
		t.Errorf("Name() = %q, want %q", d.Name(), "form")
	}
}

func TestFormDiscoverer_Discover(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		expectedParams []core.Parameter
	}{
		{
			name: "simple GET form",
			body: `<html><body>
				<form method="GET" action="/search">
					<input type="text" name="q" value="test">
					<input type="submit" value="Search">
				</form>
			</body></html>`,
			expectedParams: []core.Parameter{
				{Name: "q", Location: core.ParamLocationQuery, Value: "test", Type: "string"},
			},
		},
		{
			name: "POST form with multiple inputs",
			body: `<html><body>
				<form method="POST" action="/login">
					<input type="text" name="username">
					<input type="password" name="password">
					<input type="hidden" name="csrf_token" value="abc123">
					<input type="submit" value="Login">
				</form>
			</body></html>`,
			expectedParams: []core.Parameter{
				{Name: "username", Location: core.ParamLocationBody, Type: "string"},
				{Name: "password", Location: core.ParamLocationBody, Type: "string"},
				{Name: "csrf_token", Location: core.ParamLocationBody, Value: "abc123", Type: "string"},
			},
		},
		{
			name: "form with textarea and select",
			body: `<html><body>
				<form method="POST" action="/submit">
					<textarea name="comment">hello</textarea>
					<select name="category">
						<option value="1">Cat 1</option>
						<option value="2">Cat 2</option>
					</select>
				</form>
			</body></html>`,
			expectedParams: []core.Parameter{
				{Name: "comment", Location: core.ParamLocationBody, Value: "hello", Type: "string"},
				{Name: "category", Location: core.ParamLocationBody, Type: "string"},
			},
		},
		{
			name: "form without method defaults to GET",
			body: `<html><body>
				<form action="/search">
					<input type="text" name="q">
				</form>
			</body></html>`,
			expectedParams: []core.Parameter{
				{Name: "q", Location: core.ParamLocationQuery, Type: "string"},
			},
		},
		{
			name: "skips file and button inputs",
			body: `<html><body>
				<form method="POST" action="/upload">
					<input type="text" name="title">
					<input type="file" name="attachment">
					<input type="button" name="btn">
					<input type="image" name="img">
					<input type="reset" name="rst">
				</form>
			</body></html>`,
			expectedParams: []core.Parameter{
				{Name: "title", Location: core.ParamLocationBody, Type: "string"},
			},
		},
		{
			name: "skips inputs without name",
			body: `<html><body>
				<form method="POST">
					<input type="text" name="valid">
					<input type="text">
				</form>
			</body></html>`,
			expectedParams: []core.Parameter{
				{Name: "valid", Location: core.ParamLocationBody, Type: "string"},
			},
		},
		{
			name: "no forms",
			body: `<html><body><p>No forms here</p></body></html>`,
		},
		{
			name:           "empty body",
			body:           "",
			expectedParams: nil,
		},
		{
			name: "checkbox and radio inputs",
			body: `<html><body>
				<form method="POST">
					<input type="checkbox" name="agree" value="yes">
					<input type="radio" name="plan" value="pro">
				</form>
			</body></html>`,
			expectedParams: []core.Parameter{
				{Name: "agree", Location: core.ParamLocationBody, Value: "yes", Type: "string"},
				{Name: "plan", Location: core.ParamLocationBody, Value: "pro", Type: "string"},
			},
		},
	}

	d := NewFormDiscoverer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{Body: tt.body}
			params, err := d.Discover(context.Background(), "http://example.com", resp)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
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

func TestFormDiscoverer_NilResponse(t *testing.T) {
	d := NewFormDiscoverer()
	params, err := d.Discover(context.Background(), "http://example.com", nil)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if params != nil {
		t.Errorf("Discover() with nil response = %v, want nil", params)
	}
}

package discovery

import (
	"context"
	"testing"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

func TestMultipartDiscoverer_Name(t *testing.T) {
	d := NewMultipartDiscoverer()
	if d.Name() != "multipart" {
		t.Errorf("Name() = %q, want %q", d.Name(), "multipart")
	}
}

func TestMultipartDiscoverer_Discover(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		expectedParams []core.Parameter
		expectEmpty    bool
	}{
		{
			name: "multipart form with inputs",
			body: `<html><body>
				<form enctype="multipart/form-data" method="POST" action="/upload">
					<input type="text" name="title">
					<input type="file" name="document">
					<input type="hidden" name="csrf" value="abc">
				</form>
			</body></html>`,
			expectedParams: []core.Parameter{
				{Name: "title", Location: core.ParamLocationBody},
				{Name: "document", Location: core.ParamLocationBody},
				{Name: "csrf", Location: core.ParamLocationBody},
			},
		},
		{
			name: "multiple multipart forms",
			body: `<html><body>
				<form enctype="multipart/form-data" action="/upload1">
					<input name="file1">
				</form>
				<form enctype="multipart/form-data" action="/upload2">
					<input name="file2">
				</form>
			</body></html>`,
			expectedParams: []core.Parameter{
				{Name: "file1", Location: core.ParamLocationBody},
				{Name: "file2", Location: core.ParamLocationBody},
			},
		},
		{
			name: "non-multipart form is ignored",
			body: `<html><body>
				<form method="POST" action="/login">
					<input name="username">
				</form>
			</body></html>`,
			expectEmpty: true,
		},
		{
			name: "no forms at all",
			body: `<html><body><p>No forms here</p></body></html>`,
			expectEmpty: true,
		},
		{
			name:        "empty body",
			body:        "",
			expectEmpty: true,
		},
		{
			name: "case insensitive enctype check",
			body: `<html><body>
				<form ENCTYPE="MULTIPART/FORM-DATA" action="/upload">
					<input name="photo">
				</form>
			</body></html>`,
			expectedParams: []core.Parameter{
				{Name: "photo", Location: core.ParamLocationBody},
			},
		},
		{
			name: "mixed multipart and regular forms",
			body: `<html><body>
				<form method="POST" action="/login">
					<input name="username">
				</form>
				<form enctype="multipart/form-data" action="/upload">
					<input name="avatar">
				</form>
			</body></html>`,
			expectedParams: []core.Parameter{
				{Name: "avatar", Location: core.ParamLocationBody},
			},
		},
		{
			name: "skips inputs without name",
			body: `<html><body>
				<form enctype="multipart/form-data" action="/upload">
					<input type="text" name="title">
					<input type="text">
				</form>
			</body></html>`,
			expectedParams: []core.Parameter{
				{Name: "title", Location: core.ParamLocationBody},
			},
		},
	}

	d := NewMultipartDiscoverer()

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

func TestMultipartDiscoverer_NilResponse(t *testing.T) {
	d := NewMultipartDiscoverer()
	params, err := d.Discover(context.Background(), "http://example.com", nil)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if params != nil {
		t.Errorf("Discover() with nil response = %v, want nil", params)
	}
}

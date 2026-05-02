package discovery

import (
	"context"
	"testing"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
)

func TestPathSegmentDiscoverer_Name(t *testing.T) {
	d := NewPathSegmentDiscoverer()
	if d.Name() != "pathsegment" {
		t.Errorf("Name() = %q, want %q", d.Name(), "pathsegment")
	}
}

func TestPathSegmentDiscoverer_Discover(t *testing.T) {
	tests := []struct {
		name           string
		url            string
		expectedParams []core.Parameter
	}{
		{
			name: "numeric ID",
			url:  "http://example.com/users/12345/profile",
			expectedParams: []core.Parameter{
				{Name: "path_1", Location: core.ParamLocationPath, Value: "12345", Type: "number"},
			},
		},
		{
			name: "UUID",
			url:  "http://example.com/items/550e8400-e29b-41d4-a716-446655440000/detail",
			expectedParams: []core.Parameter{
				{Name: "path_1", Location: core.ParamLocationPath, Value: "550e8400-e29b-41d4-a716-446655440000", Type: "string"},
			},
		},
		{
			name: "base64 encoded segment",
			url:  "http://example.com/data/dXNlcm5hbWU6cGFzc3dvcmQ=/view",
			expectedParams: []core.Parameter{
				{Name: "path_1", Location: core.ParamLocationPath, Value: "dXNlcm5hbWU6cGFzc3dvcmQ=", Type: "string"},
			},
		},
		{
			name: "hex segment",
			url:  "http://example.com/token/deadbeef1234abcd",
			expectedParams: []core.Parameter{
				{Name: "path_1", Location: core.ParamLocationPath, Value: "deadbeef1234abcd", Type: "string"},
			},
		},
		{
			name: "resource prefix detection",
			url:  "http://example.com/users/john-doe/profile",
			expectedParams: []core.Parameter{
				{Name: "path_1", Location: core.ParamLocationPath, Value: "john-doe", Type: "string"},
			},
		},
		{
			name: "multiple injectable segments",
			url:  "http://example.com/users/42/posts/99",
			expectedParams: []core.Parameter{
				{Name: "path_1", Location: core.ParamLocationPath, Value: "42", Type: "number"},
				{Name: "path_3", Location: core.ParamLocationPath, Value: "99", Type: "number"},
			},
		},
		{
			name:           "no injectable segments",
			url:            "http://example.com/about/contact",
			expectedParams: nil,
		},
		{
			name:           "root path",
			url:            "http://example.com/",
			expectedParams: nil,
		},
		{
			name: "products resource prefix",
			url:  "http://example.com/products/super-widget/reviews",
			expectedParams: []core.Parameter{
				{Name: "path_1", Location: core.ParamLocationPath, Value: "super-widget", Type: "string"},
			},
		},
	}

	d := NewPathSegmentDiscoverer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := d.Discover(context.Background(), tt.url, nil)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}

			if tt.expectedParams == nil {
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
					if p.Name == expected.Name && p.Value == expected.Value {
						found = true
						if p.Location != expected.Location {
							t.Errorf("param %q location = %q, want %q", expected.Name, p.Location, expected.Location)
						}
						if p.Type != expected.Type {
							t.Errorf("param %q type = %q, want %q", expected.Name, p.Type, expected.Type)
						}
						break
					}
				}
				if !found {
					t.Errorf("missing expected param: Name=%q Value=%q", expected.Name, expected.Value)
				}
			}
		})
	}
}

package discovery

import (
	"context"
	"testing"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

func TestRobotsSitemapDiscoverer_Name(t *testing.T) {
	d := NewRobotsSitemapDiscoverer()
	if d.Name() != "robotsitemap" {
		t.Errorf("Name() = %q, want %q", d.Name(), "robotsitemap")
	}
}

func TestRobotsSitemapDiscoverer_Discover(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		expectedParams []core.Parameter
		expectEmpty    bool
	}{
		{
			name: "robots.txt with Disallow paths",
			body: `User-agent: *
Disallow: /admin/
Disallow: /api/internal/
Allow: /api/public/`,
			expectedParams: []core.Parameter{
				{Name: "admin", Location: core.ParamLocationPath},
				{Name: "api", Location: core.ParamLocationPath},
				{Name: "internal", Location: core.ParamLocationPath},
				{Name: "public", Location: core.ParamLocationPath},
			},
		},
		{
			name: "robots.txt with single segment paths",
			body: `User-agent: *
Disallow: /secret
Disallow: /private`,
			expectedParams: []core.Parameter{
				{Name: "secret", Location: core.ParamLocationPath},
				{Name: "private", Location: core.ParamLocationPath},
			},
		},
		{
			name: "deduplicates path segments",
			body: `User-agent: *
Disallow: /admin/panel
Allow: /admin/login`,
			expectedParams: []core.Parameter{
				{Name: "admin", Location: core.ParamLocationPath},
				{Name: "panel", Location: core.ParamLocationPath},
				{Name: "login", Location: core.ParamLocationPath},
			},
		},
		{
			name:        "empty body",
			body:        "",
			expectEmpty: true,
		},
		{
			name: "no Disallow or Allow directives",
			body: `User-agent: *
Crawl-delay: 10
Sitemap: http://example.com/sitemap.xml`,
			expectEmpty: true,
		},
		{
			name: "Allow directive paths",
			body: `User-agent: *
Allow: /public/docs/
Allow: /public/images/`,
			expectedParams: []core.Parameter{
				{Name: "public", Location: core.ParamLocationPath},
				{Name: "docs", Location: core.ParamLocationPath},
				{Name: "images", Location: core.ParamLocationPath},
			},
		},
	}

	d := NewRobotsSitemapDiscoverer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{Body: tt.body}
			params, err := d.Discover(context.Background(), "http://example.com/robots.txt", resp)
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

func TestRobotsSitemapDiscoverer_NilResponse(t *testing.T) {
	d := NewRobotsSitemapDiscoverer()
	params, err := d.Discover(context.Background(), "http://example.com", nil)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if params != nil {
		t.Errorf("Discover() with nil response = %v, want nil", params)
	}
}

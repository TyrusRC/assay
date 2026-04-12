package discovery

import (
	"context"
	"testing"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

func TestXMLBodyDiscoverer_Name(t *testing.T) {
	d := NewXMLBodyDiscoverer()
	if d.Name() != "xmlbody" {
		t.Errorf("Name() = %q, want %q", d.Name(), "xmlbody")
	}
}

func TestXMLBodyDiscoverer_Discover(t *testing.T) {
	tests := []struct {
		name           string
		contentType    string
		body           string
		expectedParams []core.Parameter
		expectEmpty    bool
	}{
		{
			name:        "application/xml content type",
			contentType: "application/xml",
			body:        `<root><username>admin</username><password>secret</password></root>`,
			expectedParams: []core.Parameter{
				{Name: "root", Location: core.ParamLocationBody},
				{Name: "username", Location: core.ParamLocationBody},
				{Name: "password", Location: core.ParamLocationBody},
			},
		},
		{
			name:        "text/xml content type",
			contentType: "text/xml",
			body:        `<request><action>login</action><token>abc</token></request>`,
			expectedParams: []core.Parameter{
				{Name: "request", Location: core.ParamLocationBody},
				{Name: "action", Location: core.ParamLocationBody},
				{Name: "token", Location: core.ParamLocationBody},
			},
		},
		{
			name:        "skips common HTML structural tags",
			contentType: "application/xml",
			body:        `<html><head><title>Test</title></head><body><div><username>admin</username></div></body>`,
			expectedParams: []core.Parameter{
				{Name: "title", Location: core.ParamLocationBody},
				{Name: "username", Location: core.ParamLocationBody},
			},
		},
		{
			name:        "element with attributes",
			contentType: "application/xml",
			body:        `<user id="1"><name>test</name></user>`,
			expectedParams: []core.Parameter{
				{Name: "user", Location: core.ParamLocationBody},
				{Name: "name", Location: core.ParamLocationBody},
			},
		},
		{
			name:        "self-closing element",
			contentType: "application/xml",
			body:        `<root><item /><field>val</field></root>`,
			expectedParams: []core.Parameter{
				{Name: "root", Location: core.ParamLocationBody},
				{Name: "item", Location: core.ParamLocationBody},
				{Name: "field", Location: core.ParamLocationBody},
			},
		},
		{
			name:        "deduplicates element names",
			contentType: "text/xml",
			body:        `<items><item>a</item><item>b</item></items>`,
			expectedParams: []core.Parameter{
				{Name: "items", Location: core.ParamLocationBody},
				{Name: "item", Location: core.ParamLocationBody},
			},
		},
		{
			name:        "non-XML content type",
			contentType: "text/html",
			body:        `<root><data>test</data></root>`,
			expectEmpty: true,
		},
		{
			name:        "empty body",
			contentType: "application/xml",
			body:        "",
			expectEmpty: true,
		},
		{
			name:        "element with hyphen and underscore",
			contentType: "application/xml",
			body:        `<user-info><first_name>test</first_name></user-info>`,
			expectedParams: []core.Parameter{
				{Name: "user-info", Location: core.ParamLocationBody},
				{Name: "first_name", Location: core.ParamLocationBody},
			},
		},
	}

	d := NewXMLBodyDiscoverer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Body:        tt.body,
				ContentType: tt.contentType,
			}
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

func TestXMLBodyDiscoverer_NilResponse(t *testing.T) {
	d := NewXMLBodyDiscoverer()
	params, err := d.Discover(context.Background(), "http://example.com", nil)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if params != nil {
		t.Errorf("Discover() with nil response = %v, want nil", params)
	}
}

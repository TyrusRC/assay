package discovery

import (
	"context"
	"testing"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

func TestJSStorageDiscoverer_Name(t *testing.T) {
	d := NewJSStorageDiscoverer()
	if d.Name() != "jsstorage" {
		t.Errorf("Name() = %q, want %q", d.Name(), "jsstorage")
	}
}

func TestJSStorageDiscoverer_Discover(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		expectedParams []core.Parameter
	}{
		{
			name: "localStorage.setItem with double quotes",
			body: `<script>localStorage.setItem("authToken", token);</script>`,
			expectedParams: []core.Parameter{
				{Name: "authToken", Location: core.ParamLocationLocalStorage},
			},
		},
		{
			name: "localStorage.setItem with single quotes",
			body: `<script>localStorage.setItem('userPrefs', data);</script>`,
			expectedParams: []core.Parameter{
				{Name: "userPrefs", Location: core.ParamLocationLocalStorage},
			},
		},
		{
			name: "sessionStorage.setItem",
			body: `<script>sessionStorage.setItem("tempData", val);</script>`,
			expectedParams: []core.Parameter{
				{Name: "tempData", Location: core.ParamLocationSessionStorage},
			},
		},
		{
			name: "bracket notation",
			body: `<script>
				localStorage["darkMode"] = true;
				sessionStorage['cartItems'] = JSON.stringify(items);
			</script>`,
			expectedParams: []core.Parameter{
				{Name: "darkMode", Location: core.ParamLocationLocalStorage},
				{Name: "cartItems", Location: core.ParamLocationSessionStorage},
			},
		},
		{
			name: "dot notation assignment",
			body: `<script>
				localStorage.theme = "dark";
				sessionStorage.step = "3";
			</script>`,
			expectedParams: []core.Parameter{
				{Name: "theme", Location: core.ParamLocationLocalStorage},
				{Name: "step", Location: core.ParamLocationSessionStorage},
			},
		},
		{
			name: "document.cookie assignment",
			body: `<script>document.cookie = "tracking=abc123; path=/";</script>`,
			expectedParams: []core.Parameter{
				{Name: "tracking", Location: core.ParamLocationCookie},
			},
		},
		{
			name: "mixed storage types",
			body: `<script>
				localStorage.setItem("token", jwt);
				sessionStorage.setItem("csrf", token);
				document.cookie = "session=xyz";
			</script>`,
			expectedParams: []core.Parameter{
				{Name: "token", Location: core.ParamLocationLocalStorage},
				{Name: "csrf", Location: core.ParamLocationSessionStorage},
				{Name: "session", Location: core.ParamLocationCookie},
			},
		},
		{
			name: "skips built-in methods in dot notation",
			body: `<script>
				localStorage.setItem = customFn;
				localStorage.getItem = customFn;
				localStorage.clear = customFn;
				localStorage.userData = "test";
			</script>`,
			expectedParams: []core.Parameter{
				{Name: "userData", Location: core.ParamLocationLocalStorage},
			},
		},
		{
			name: "deduplicates same key from different patterns",
			body: `<script>
				localStorage.setItem("key1", "a");
				localStorage["key1"] = "b";
			</script>`,
			expectedParams: []core.Parameter{
				{Name: "key1", Location: core.ParamLocationLocalStorage},
			},
		},
		{
			name:           "no storage references",
			body:           `<html><body>Just regular content</body></html>`,
			expectedParams: nil,
		},
		{
			name:           "empty body",
			body:           "",
			expectedParams: nil,
		},
	}

	d := NewJSStorageDiscoverer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{Body: tt.body}
			params, err := d.Discover(context.Background(), "http://example.com", resp)
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

func TestJSStorageDiscoverer_NilResponse(t *testing.T) {
	d := NewJSStorageDiscoverer()
	params, err := d.Discover(context.Background(), "http://example.com", nil)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if params != nil {
		t.Errorf("Discover() with nil response = %v, want nil", params)
	}
}

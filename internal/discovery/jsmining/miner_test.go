package jsmining

import (
	"sort"
	"strings"
	"testing"
)

func TestMine_TableDriven(t *testing.T) {
	tests := []struct {
		name    string
		js      string
		baseURL string
		want    []string
	}{
		{
			name:    "empty source returns nothing",
			js:      "",
			baseURL: "https://example.com",
			want:    nil,
		},
		{
			name:    "fetch with absolute path",
			js:      `fetch("/api/v1/users")`,
			baseURL: "https://example.com",
			want:    []string{"https://example.com/api/v1/users"},
		},
		{
			name:    "fetch with single quotes",
			js:      `fetch('/api/v1/items')`,
			baseURL: "https://example.com",
			want:    []string{"https://example.com/api/v1/items"},
		},
		{
			name:    "axios.get and axios.post",
			js:      `axios.get("/api/orders"); axios.post("/api/orders", body);`,
			baseURL: "https://example.com",
			want:    []string{"https://example.com/api/orders"},
		},
		{
			name:    "jquery ajax url",
			js:      `$.ajax({url:"/api/legacy/list", method:"GET"});`,
			baseURL: "https://example.com",
			want:    []string{"https://example.com/api/legacy/list"},
		},
		{
			name:    "XMLHttpRequest open call",
			js:      `var x=new XMLHttpRequest();x.open("GET","/api/xhr/users",true);`,
			baseURL: "https://example.com",
			want:    []string{"https://example.com/api/xhr/users"},
		},
		{
			name:    "path template with curly braces",
			js:      `const URL = "/api/v1/users/{id}/profile";`,
			baseURL: "https://example.com",
			want:    []string{"https://example.com/api/v1/users/{id}/profile"},
		},
		{
			name:    "path with regex-like segment",
			js:      `var pat = "/users/[0-9]+/profile";`,
			baseURL: "https://example.com",
			want:    []string{"https://example.com/users/[0-9]+/profile"},
		},
		{
			name:    "constant endpoint",
			js:      `const ENDPOINT = "/api/x";`,
			baseURL: "https://example.com",
			want:    []string{"https://example.com/api/x"},
		},
		{
			name:    "absolute URL is preserved",
			js:      `fetch("https://api.other.com/v1/things")`,
			baseURL: "https://example.com",
			want:    []string{"https://api.other.com/v1/things"},
		},
		{
			name:    "duplicates collapse",
			js:      `fetch("/api/dup"); axios.get("/api/dup");`,
			baseURL: "https://example.com",
			want:    []string{"https://example.com/api/dup"},
		},
		{
			name:    "minified bundle mix",
			js:      `function a(){return fetch("/api/a")}function b(){axios.post("/api/b",{})}var E="/api/c";`,
			baseURL: "https://example.com",
			want: []string{
				"https://example.com/api/a",
				"https://example.com/api/b",
				"https://example.com/api/c",
			},
		},
		{
			name:    "ignores non-endpoint short strings",
			js:      `var x = "hello"; var y = "GET";`,
			baseURL: "https://example.com",
			want:    nil,
		},
		{
			name:    "ignores plain comments without url shape",
			js:      `// not an endpoint`,
			baseURL: "https://example.com",
			want:    nil,
		},
		{
			name:    "no baseURL leaves absolute paths unresolved",
			js:      `fetch("/api/u")`,
			baseURL: "",
			want:    []string{"/api/u"},
		},
		{
			name:    "data: and javascript: schemes are ignored",
			js:      `fetch("data:text/plain,hi"); fetch("javascript:void(0)");`,
			baseURL: "https://example.com",
			want:    nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Mine(tc.js, tc.baseURL)
			sort.Strings(got)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			if !equalStringSlices(got, want) {
				t.Errorf("Mine() =\n  got:  %v\n  want: %v", got, want)
			}
		})
	}
}

func TestMine_Dedup(t *testing.T) {
	js := strings.Repeat(`fetch("/api/same");`, 5)
	got := Mine(js, "https://example.com")
	if len(got) != 1 || got[0] != "https://example.com/api/same" {
		t.Errorf("dedup failed: %v", got)
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

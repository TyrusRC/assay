package cspt

import "testing"

func TestAnalyze_PositiveCases(t *testing.T) {
	cases := []struct {
		name string
		js   string
	}{
		{
			name: "string concat fetch path with query-param source",
			js:   `const id = new URLSearchParams(location.search).get('id'); fetch('/api/v1/users/' + id);`,
		},
		{
			name: "template literal fetch path with hash source",
			js:   "var p = location.hash.slice(1); fetch(`/api/data/${p}/info`);",
		},
		{
			name: "xhr open path concat with router param",
			js:   `const name = useParams().name; xhr.open('GET', '/profile/' + name);`,
		},
		{
			name: "axios get path concat with document.URL",
			js:   `let seg = document.URL.split('/').pop(); axios.get('/files/' + seg);`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sinks := Analyze(tc.js)
			if len(sinks) == 0 {
				t.Fatalf("expected a CSPT sink, got none for %q", tc.js)
			}
		})
	}
}

func TestAnalyze_NegativeCases(t *testing.T) {
	cases := []struct {
		name string
		js   string
	}{
		{
			name: "tainted value lands in query string, not path",
			js:   `const id = new URLSearchParams(location.search).get('id'); fetch('/api/users?id=' + id);`,
		},
		{
			name: "no tainted source",
			js:   `fetch('/api/' + 'static/list');`,
		},
		{
			name: "static full url",
			js:   `fetch('https://api.example.com/v1/items');`,
		},
		{
			name: "tainted value is a full url (open redirect/ssrf, not cspt)",
			js:   `const u = location.href; fetch(u);`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sinks := Analyze(tc.js)
			if len(sinks) != 0 {
				t.Fatalf("expected no CSPT sink, got %d for %q: %+v", len(sinks), tc.js, sinks)
			}
		})
	}
}

func TestAnalyze_ReportsCallTypeAndSource(t *testing.T) {
	js := `const id = new URLSearchParams(location.search).get('id'); fetch('/api/v1/users/' + id);`
	sinks := Analyze(js)
	if len(sinks) != 1 {
		t.Fatalf("expected 1 sink, got %d", len(sinks))
	}
	if sinks[0].Call != "fetch" {
		t.Errorf("expected call=fetch, got %q", sinks[0].Call)
	}
	if sinks[0].Snippet == "" {
		t.Error("expected a non-empty snippet")
	}
}

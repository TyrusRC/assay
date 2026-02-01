package parser

import (
	"testing"
)

func TestParseBytes_TimeMatcherValid(t *testing.T) {
	yaml := `
id: time-matcher-test
info:
  name: Time Matcher Test
http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    matchers:
      - type: time
        dsl:
          - "> 5s"
`
	p := New()
	tmpl, err := p.ParseBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseBytes() error for time matcher: %v", err)
	}
	if len(tmpl.HTTP[0].Matchers) != 1 {
		t.Error("Expected 1 matcher")
	}
	if tmpl.HTTP[0].Matchers[0].Type != "time" {
		t.Errorf("Matcher type = %q, want time", tmpl.HTTP[0].Matchers[0].Type)
	}
}

func TestParseBytes_TimeMatcherNoDSL(t *testing.T) {
	yaml := `
id: time-matcher-no-dsl
info:
  name: Time Matcher No DSL
http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    matchers:
      - type: time
`
	p := New()
	_, err := p.ParseBytes([]byte(yaml))
	if err == nil {
		t.Error("Expected error for time matcher without DSL expressions")
	}
}

func TestParseBytes_XPathMatcherValid(t *testing.T) {
	yaml := `
id: xpath-matcher-test
info:
  name: XPath Matcher Test
http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    matchers:
      - type: xpath
        xpath:
          - "//div[@id='main']"
`
	p := New()
	tmpl, err := p.ParseBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseBytes() error for xpath matcher: %v", err)
	}
	if len(tmpl.HTTP[0].Matchers) != 1 {
		t.Error("Expected 1 matcher")
	}
	if tmpl.HTTP[0].Matchers[0].Type != "xpath" {
		t.Errorf("Matcher type = %q, want xpath", tmpl.HTTP[0].Matchers[0].Type)
	}
}

func TestParseBytes_XPathMatcherNoXPath(t *testing.T) {
	yaml := `
id: xpath-matcher-no-xpath
info:
  name: XPath Matcher No XPath
http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    matchers:
      - type: xpath
`
	p := New()
	_, err := p.ParseBytes([]byte(yaml))
	if err == nil {
		t.Error("Expected error for xpath matcher without xpath expressions")
	}
}

func TestParseBytes_XPathMatcherMultiple(t *testing.T) {
	yaml := `
id: xpath-matcher-multiple
info:
  name: XPath Matcher Multiple
http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    matchers:
      - type: xpath
        xpath:
          - "//form[@action='/login']"
          - "//input[@type='password']"
        condition: and
`
	p := New()
	tmpl, err := p.ParseBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseBytes() error: %v", err)
	}
	if len(tmpl.HTTP[0].Matchers[0].XPath) != 2 {
		t.Errorf("XPath len = %d, want 2", len(tmpl.HTTP[0].Matchers[0].XPath))
	}
}

func TestParseBytes_CombinedMatchers(t *testing.T) {
	yaml := `
id: combined-matchers
info:
  name: Combined Matchers Test
http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    matchers:
      - type: status
        status:
          - 200
      - type: xpath
        xpath:
          - "//div[@class='vulnerable']"
      - type: time
        dsl:
          - "> 5s"
    matchers-condition: and
`
	p := New()
	tmpl, err := p.ParseBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseBytes() error: %v", err)
	}
	if len(tmpl.HTTP[0].Matchers) != 3 {
		t.Errorf("Matchers len = %d, want 3", len(tmpl.HTTP[0].Matchers))
	}
}

func TestParseBytes_AllMatcherTypes(t *testing.T) {
	tests := []struct {
		name        string
		matcherType string
		yaml        string
		shouldError bool
	}{
		{
			name:        "word matcher",
			matcherType: "word",
			yaml: `
id: test
info:
  name: Test
http:
  - path: ["/"]
    matchers:
      - type: word
        words: ["test"]
`,
			shouldError: false,
		},
		{
			name:        "regex matcher",
			matcherType: "regex",
			yaml: `
id: test
info:
  name: Test
http:
  - path: ["/"]
    matchers:
      - type: regex
        regex: ["test.*"]
`,
			shouldError: false,
		},
		{
			name:        "status matcher",
			matcherType: "status",
			yaml: `
id: test
info:
  name: Test
http:
  - path: ["/"]
    matchers:
      - type: status
        status: [200]
`,
			shouldError: false,
		},
		{
			name:        "size matcher",
			matcherType: "size",
			yaml: `
id: test
info:
  name: Test
http:
  - path: ["/"]
    matchers:
      - type: size
        size: [1024]
`,
			shouldError: false,
		},
		{
			name:        "binary matcher",
			matcherType: "binary",
			yaml: `
id: test
info:
  name: Test
http:
  - path: ["/"]
    matchers:
      - type: binary
        binary: ["89504E47"]
`,
			shouldError: false,
		},
		{
			name:        "dsl matcher",
			matcherType: "dsl",
			yaml: `
id: test
info:
  name: Test
http:
  - path: ["/"]
    matchers:
      - type: dsl
        dsl: ["status_code == 200"]
`,
			shouldError: false,
		},
		{
			name:        "xpath matcher",
			matcherType: "xpath",
			yaml: `
id: test
info:
  name: Test
http:
  - path: ["/"]
    matchers:
      - type: xpath
        xpath: ["//div"]
`,
			shouldError: false,
		},
		{
			name:        "time matcher",
			matcherType: "time",
			yaml: `
id: test
info:
  name: Test
http:
  - path: ["/"]
    matchers:
      - type: time
        dsl: ["> 5s"]
`,
			shouldError: false,
		},
		{
			name:        "unknown matcher type",
			matcherType: "unknown",
			yaml: `
id: test
info:
  name: Test
http:
  - path: ["/"]
    matchers:
      - type: unknown
`,
			shouldError: true,
		},
	}

	p := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := p.ParseBytes([]byte(tt.yaml))
			if tt.shouldError && err == nil {
				t.Errorf("Expected error for matcher type %q", tt.matcherType)
			}
			if !tt.shouldError && err != nil {
				t.Errorf("Unexpected error for matcher type %q: %v", tt.matcherType, err)
			}
		})
	}
}

func TestParseBytes_BinaryMatcherNoBinary(t *testing.T) {
	yaml := `
id: binary-matcher-no-binary
info:
  name: Binary Matcher No Binary
http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    matchers:
      - type: binary
`
	p := New()
	_, err := p.ParseBytes([]byte(yaml))
	if err == nil {
		t.Error("Expected error for binary matcher without binary patterns")
	}
}

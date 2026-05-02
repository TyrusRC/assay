package matchers

import (
	"testing"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates"
)

func TestMatchXPath_HTML(t *testing.T) {
	e := New()

	htmlContent := `<!DOCTYPE html>
<html>
<head><title>Test Page</title></head>
<body>
	<div id="main">
		<h1 class="title">Welcome</h1>
		<p class="content">Hello World</p>
		<form action="/login" method="post">
			<input type="text" name="username" />
			<input type="password" name="password" />
			<button type="submit">Login</button>
		</form>
		<a href="/admin">Admin Panel</a>
	</div>
</body>
</html>`

	tests := []struct {
		name        string
		xpath       []string
		expectMatch bool
	}{
		{
			name:        "Find element by ID",
			xpath:       []string{`//div[@id="main"]`},
			expectMatch: true,
		},
		{
			name:        "Find element by class",
			xpath:       []string{`//h1[@class="title"]`},
			expectMatch: true,
		},
		{
			name:        "Find form with action",
			xpath:       []string{`//form[@action="/login"]`},
			expectMatch: true,
		},
		{
			name:        "Find password input",
			xpath:       []string{`//input[@type="password"]`},
			expectMatch: true,
		},
		{
			name:        "Find admin link",
			xpath:       []string{`//a[@href="/admin"]`},
			expectMatch: true,
		},
		{
			name:        "Find non-existent element",
			xpath:       []string{`//div[@id="nonexistent"]`},
			expectMatch: false,
		},
		{
			name:        "Find element with text content",
			xpath:       []string{`//p[contains(text(), "Hello")]`},
			expectMatch: true,
		},
		{
			name:        "Find title element",
			xpath:       []string{`//title[text()="Test Page"]`},
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &Response{
				Body:        htmlContent,
				ContentType: "text/html",
			}
			matcher := &templates.Matcher{
				Type:  "xpath",
				XPath: tt.xpath,
			}
			result := e.Match(matcher, resp, nil)
			if result.Matched != tt.expectMatch {
				t.Errorf("matchXPath() = %v, want %v", result.Matched, tt.expectMatch)
			}
		})
	}
}

func TestMatchXPath_XML(t *testing.T) {
	e := New()

	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<catalog>
	<book id="bk101">
		<author>Gambardella, Matthew</author>
		<title>XML Developer's Guide</title>
		<price>44.95</price>
	</book>
	<book id="bk102">
		<author>Ralls, Kim</author>
		<title>Midnight Rain</title>
		<price>5.95</price>
	</book>
</catalog>`

	tests := []struct {
		name        string
		xpath       []string
		expectMatch bool
	}{
		{
			name:        "Find book by ID",
			xpath:       []string{`//book[@id="bk101"]`},
			expectMatch: true,
		},
		{
			name:        "Find author",
			xpath:       []string{`//author[text()="Ralls, Kim"]`},
			expectMatch: true,
		},
		{
			name:        "Find book with price > 10",
			xpath:       []string{`//book[price > 10]`},
			expectMatch: true,
		},
		{
			name:        "Find non-existent book",
			xpath:       []string{`//book[@id="bk999"]`},
			expectMatch: false,
		},
		{
			name:        "Count books",
			xpath:       []string{`count(//book) = 2`},
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &Response{
				Body:        xmlContent,
				ContentType: "application/xml",
			}
			matcher := &templates.Matcher{
				Type:  "xpath",
				XPath: tt.xpath,
			}
			result := e.Match(matcher, resp, nil)
			if result.Matched != tt.expectMatch {
				t.Errorf("matchXPath() = %v, want %v", result.Matched, tt.expectMatch)
			}
		})
	}
}

func TestMatchXPath_Conditions(t *testing.T) {
	e := New()

	htmlContent := `<html><body>
		<div class="error">Error message</div>
		<div class="success">Success message</div>
	</body></html>`

	tests := []struct {
		name        string
		xpath       []string
		condition   string
		expectMatch bool
	}{
		{
			name:        "OR condition - one matches",
			xpath:       []string{`//div[@class="error"]`, `//div[@class="notfound"]`},
			condition:   "or",
			expectMatch: true,
		},
		{
			name:        "AND condition - all match",
			xpath:       []string{`//div[@class="error"]`, `//div[@class="success"]`},
			condition:   "and",
			expectMatch: true,
		},
		{
			name:        "AND condition - one fails",
			xpath:       []string{`//div[@class="error"]`, `//div[@class="notfound"]`},
			condition:   "and",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &Response{
				Body:        htmlContent,
				ContentType: "text/html",
			}
			matcher := &templates.Matcher{
				Type:      "xpath",
				XPath:     tt.xpath,
				Condition: tt.condition,
			}
			result := e.Match(matcher, resp, nil)
			if result.Matched != tt.expectMatch {
				t.Errorf("matchXPath() = %v, want %v", result.Matched, tt.expectMatch)
			}
		})
	}
}

func TestMatchXPath_Negative(t *testing.T) {
	e := New()

	htmlContent := `<html><body><div id="admin">Admin Area</div></body></html>`
	resp := &Response{
		Body:        htmlContent,
		ContentType: "text/html",
	}

	matcher := &templates.Matcher{
		Type:     "xpath",
		XPath:    []string{`//div[@id="admin"]`},
		Negative: true,
	}

	result := e.Match(matcher, resp, nil)
	if result.Matched {
		t.Error("Negative XPath matcher should not match when element exists")
	}
}

func TestMatchXPath_InvalidXPath(t *testing.T) {
	e := New()

	htmlContent := `<html><body><div>Test</div></body></html>`
	resp := &Response{
		Body:        htmlContent,
		ContentType: "text/html",
	}

	matcher := &templates.Matcher{
		Type:  "xpath",
		XPath: []string{`[[[invalid xpath`},
	}

	result := e.Match(matcher, resp, nil)
	if result.Matched {
		t.Error("Invalid XPath should not match")
	}
}

func TestMatchXPath_EmptyBody(t *testing.T) {
	e := New()

	resp := &Response{
		Body:        "",
		ContentType: "text/html",
	}

	matcher := &templates.Matcher{
		Type:  "xpath",
		XPath: []string{`//div`},
	}

	result := e.Match(matcher, resp, nil)
	if result.Matched {
		t.Error("Empty body should not match any XPath")
	}
}

func TestMatchXPath_MalformedHTML(t *testing.T) {
	e := New()

	// HTML parsers are lenient, so malformed HTML should still work
	malformedHTML := `<html><body><div class="test">Not closed properly<p>Nested`
	resp := &Response{
		Body:        malformedHTML,
		ContentType: "text/html",
	}

	matcher := &templates.Matcher{
		Type:  "xpath",
		XPath: []string{`//div[@class="test"]`},
	}

	result := e.Match(matcher, resp, nil)
	if !result.Matched {
		t.Error("Malformed HTML should still match with lenient parsing")
	}
}

func TestMatchXPath_PartSelection(t *testing.T) {
	e := New()

	// XPath should work on specified part
	resp := &Response{
		Body: `<html><body><div>Body Content</div></body></html>`,
		Headers: map[string]string{
			"X-Custom-Header": `<data><value>Header Content</value></data>`,
		},
		ContentType: "text/html",
	}

	tests := []struct {
		name        string
		part        string
		xpath       []string
		expectMatch bool
	}{
		{
			name:        "Match on body",
			part:        "body",
			xpath:       []string{`//div[text()="Body Content"]`},
			expectMatch: true,
		},
		{
			name:        "Match on all",
			part:        "all",
			xpath:       []string{`//div[text()="Body Content"]`},
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := &templates.Matcher{
				Type:  "xpath",
				XPath: tt.xpath,
				Part:  tt.part,
			}
			result := e.Match(matcher, resp, nil)
			if result.Matched != tt.expectMatch {
				t.Errorf("matchXPath() = %v, want %v", result.Matched, tt.expectMatch)
			}
		})
	}
}

func TestMatchXPath_ExtractAttribute(t *testing.T) {
	e := New()

	htmlContent := `<html><body><a href="/secret/path">Link</a></body></html>`
	resp := &Response{
		Body:        htmlContent,
		ContentType: "text/html",
	}

	matcher := &templates.Matcher{
		Type:  "xpath",
		XPath: []string{`//a/@href`},
		Name:  "extracted_href",
	}

	result := e.Match(matcher, resp, nil)
	if !result.Matched {
		t.Error("XPath attribute extraction should match")
	}
	if len(result.Extracts) == 0 {
		t.Error("XPath should extract attribute value")
	}
}

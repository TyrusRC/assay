package core

import (
	"testing"
)

func TestNewTarget(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"valid http", "http://example.com", false},
		{"valid https", "https://example.com", false},
		{"with path", "https://example.com/path", false},
		{"with port", "https://example.com:8080", false},
		{"with query", "https://example.com/path?id=1", false},
		{"empty", "", true},
		{"invalid scheme", "ftp://example.com", true},
		{"no scheme", "example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, err := NewTarget(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewTarget() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && target == nil {
				t.Error("NewTarget() returned nil target for valid URL")
			}
		})
	}
}

func TestTarget_Host(t *testing.T) {
	target, _ := NewTarget("https://example.com:8080/path")

	if target.Host() != "example.com:8080" {
		t.Errorf("Target.Host() = %q, want %q", target.Host(), "example.com:8080")
	}
}

func TestTarget_Domain(t *testing.T) {
	tests := []struct {
		name   string
		url    string
		domain string
	}{
		{"simple", "https://example.com", "example.com"},
		{"with port", "https://example.com:8080", "example.com"},
		{"subdomain", "https://www.example.com", "www.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, _ := NewTarget(tt.url)
			if target.Domain() != tt.domain {
				t.Errorf("Target.Domain() = %q, want %q", target.Domain(), tt.domain)
			}
		})
	}
}

func TestTarget_BaseURL(t *testing.T) {
	target, _ := NewTarget("https://example.com:8080/path?query=1")

	expected := "https://example.com:8080"
	if target.BaseURL() != expected {
		t.Errorf("Target.BaseURL() = %q, want %q", target.BaseURL(), expected)
	}
}

func TestTarget_IsHTTPS(t *testing.T) {
	httpsTarget, _ := NewTarget("https://example.com")
	httpTarget, _ := NewTarget("http://example.com")

	if !httpsTarget.IsHTTPS() {
		t.Error("HTTPS target should return true for IsHTTPS()")
	}
	if httpTarget.IsHTTPS() {
		t.Error("HTTP target should return false for IsHTTPS()")
	}
}

func TestTarget_InScope(t *testing.T) {
	target, _ := NewTarget("https://example.com")
	target.SetScope([]string{"*.example.com", "api.example.com"})

	tests := []struct {
		name    string
		url     string
		inScope bool
	}{
		{"exact match", "https://example.com/path", true},
		{"subdomain wildcard", "https://www.example.com/path", true},
		{"api subdomain", "https://api.example.com/path", true},
		{"different domain", "https://other.com/path", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if target.InScope(tt.url) != tt.inScope {
				t.Errorf("Target.InScope(%q) = %v, want %v", tt.url, !tt.inScope, tt.inScope)
			}
		})
	}
}

func TestNewEntryPoint(t *testing.T) {
	ep := NewEntryPoint("https://example.com/api/users", "GET")

	if ep.URL != "https://example.com/api/users" {
		t.Errorf("EntryPoint.URL = %q", ep.URL)
	}
	if ep.Method != "GET" {
		t.Errorf("EntryPoint.Method = %q", ep.Method)
	}
}

func TestEntryPoint_AddParameter(t *testing.T) {
	ep := NewEntryPoint("https://example.com/api/users", "GET")
	ep.AddParameter("id", "query", "123")
	ep.AddParameter("Authorization", "header", "Bearer token")

	if len(ep.Parameters) != 2 {
		t.Errorf("len(ep.Parameters) = %d, want 2", len(ep.Parameters))
	}

	queryParams := ep.GetParametersByLocation("query")
	if len(queryParams) != 1 {
		t.Errorf("len(queryParams) = %d, want 1", len(queryParams))
	}
}

func TestEntryPoint_HasParameter(t *testing.T) {
	ep := NewEntryPoint("https://example.com/api/users", "GET")
	ep.AddParameter("id", "query", "123")

	if !ep.HasParameter("id") {
		t.Error("EntryPoint should have parameter 'id'")
	}
	if ep.HasParameter("nonexistent") {
		t.Error("EntryPoint should not have parameter 'nonexistent'")
	}
}

func TestParameterLocationConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"query", ParamLocationQuery, "query"},
		{"body", ParamLocationBody, "body"},
		{"header", ParamLocationHeader, "header"},
		{"cookie", ParamLocationCookie, "cookie"},
		{"path", ParamLocationPath, "path"},
		{"localstorage", ParamLocationLocalStorage, "localstorage"},
		{"sessionstorage", ParamLocationSessionStorage, "sessionstorage"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("ParamLocation constant = %q, want %q", tt.constant, tt.expected)
			}
		})
	}
}

func TestParameter_IsPotentiallyVulnerable(t *testing.T) {
	tests := []struct {
		name       string
		paramName  string
		vulnerable bool
	}{
		{"id parameter", "id", true},
		{"user_id parameter", "user_id", true},
		{"file parameter", "file", true},
		{"url parameter", "url", true},
		{"path parameter", "path", true},
		{"query parameter", "query", true},
		{"search parameter", "search", true},
		{"page parameter", "page", false},
		{"limit parameter", "limit", false},
		{"random parameter", "random", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Parameter{Name: tt.paramName}
			if p.IsPotentiallyVulnerable() != tt.vulnerable {
				t.Errorf("Parameter{Name: %q}.IsPotentiallyVulnerable() = %v, want %v",
					tt.paramName, !tt.vulnerable, tt.vulnerable)
			}
		})
	}
}

func TestParameter_IsPotentiallyVulnerable_WithClassification(t *testing.T) {
	tests := []struct {
		name           string
		paramName      string
		classification string
		vulnerable     bool
	}{
		{"generic param with id classification", "x", ParamClassID, true},
		{"generic param with file classification", "x", ParamClassFile, true},
		{"generic param with url classification", "x", ParamClassURL, true},
		{"generic param with search classification", "x", ParamClassSearch, true},
		{"generic param with command classification", "x", ParamClassCommand, true},
		{"generic param with template classification", "x", ParamClassTemplate, true},
		{"generic param with generic classification", "x", ParamClassGeneric, false},
		{"known name still vulnerable without classification", "id", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Parameter{Name: tt.paramName, Classification: tt.classification}
			if p.IsPotentiallyVulnerable() != tt.vulnerable {
				t.Errorf("Parameter{Name: %q, Classification: %q}.IsPotentiallyVulnerable() = %v, want %v",
					tt.paramName, tt.classification, !tt.vulnerable, tt.vulnerable)
			}
		})
	}
}

func TestParamClassificationConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"id", ParamClassID, "id"},
		{"file", ParamClassFile, "file"},
		{"url", ParamClassURL, "url"},
		{"search", ParamClassSearch, "search"},
		{"command", ParamClassCommand, "command"},
		{"template", ParamClassTemplate, "template"},
		{"generic", ParamClassGeneric, "generic"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("ParamClass constant = %q, want %q", tt.constant, tt.expected)
			}
		})
	}
}

func TestParameter_Classify(t *testing.T) {
	tests := []struct {
		name               string
		paramName          string
		expectedClassification string
	}{
		{"id param", "id", ParamClassID},
		{"user_id param", "user_id", ParamClassID},
		{"item_id param", "item_id", ParamClassID},
		{"file param", "file", ParamClassFile},
		{"filepath param", "filepath", ParamClassFile},
		{"document param", "document", ParamClassFile},
		{"include param", "include", ParamClassFile},
		{"url param", "url", ParamClassURL},
		{"redirect param", "redirect", ParamClassURL},
		{"callback param", "callback", ParamClassURL},
		{"next param", "next", ParamClassURL},
		{"dest param", "dest", ParamClassURL},
		{"return param", "return", ParamClassURL},
		{"href param", "href", ParamClassURL},
		{"src param", "src", ParamClassURL},
		{"query param", "query", ParamClassSearch},
		{"search param", "search", ParamClassSearch},
		{"q param", "q", ParamClassSearch},
		{"keyword param", "keyword", ParamClassSearch},
		{"cmd param", "cmd", ParamClassCommand},
		{"exec param", "exec", ParamClassCommand},
		{"command param", "command", ParamClassCommand},
		{"template param", "template", ParamClassTemplate},
		{"random param", "foobar", ParamClassGeneric},
		{"page param", "page", ParamClassGeneric},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Parameter{Name: tt.paramName}
			p.Classify()
			if p.Classification != tt.expectedClassification {
				t.Errorf("Parameter{Name: %q}.Classify() classification = %q, want %q",
					tt.paramName, p.Classification, tt.expectedClassification)
			}
		})
	}
}

func TestParameter_NewFields(t *testing.T) {
	p := Parameter{
		Name:           "test",
		Location:       ParamLocationQuery,
		Value:          "value",
		Type:           "string",
		Reflected:      true,
		Classification: ParamClassID,
		ContentType:    "text/html",
		SegmentIndex:   3,
	}

	if !p.Reflected {
		t.Error("Reflected should be true")
	}
	if p.Classification != ParamClassID {
		t.Errorf("Classification = %q, want %q", p.Classification, ParamClassID)
	}
	if p.ContentType != "text/html" {
		t.Errorf("ContentType = %q, want %q", p.ContentType, "text/html")
	}
	if p.SegmentIndex != 3 {
		t.Errorf("SegmentIndex = %d, want 3", p.SegmentIndex)
	}
}

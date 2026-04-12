package core

import (
	"errors"
	"net/url"
	"strings"
)

// Target represents a scan target with its URL and scope configuration.
type Target struct {
	rawURL    string
	parsedURL *url.URL
	scope     []string
}

// NewTarget creates a new Target from a URL string.
func NewTarget(rawURL string) (*Target, error) {
	if rawURL == "" {
		return nil, errors.New("URL cannot be empty")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("URL must have http or https scheme")
	}

	return &Target{
		rawURL:    rawURL,
		parsedURL: parsed,
		scope:     []string{},
	}, nil
}

// URL returns the original URL string.
func (t *Target) URL() string {
	return t.rawURL
}

// Host returns the host portion of the URL (including port if present).
func (t *Target) Host() string {
	return t.parsedURL.Host
}

// Domain returns the domain name without port.
func (t *Target) Domain() string {
	return t.parsedURL.Hostname()
}

// BaseURL returns the scheme and host without path.
func (t *Target) BaseURL() string {
	return t.parsedURL.Scheme + "://" + t.parsedURL.Host
}

// IsHTTPS returns true if the target uses HTTPS.
func (t *Target) IsHTTPS() bool {
	return t.parsedURL.Scheme == "https"
}

// SetScope sets the allowed scope patterns.
func (t *Target) SetScope(patterns []string) {
	t.scope = patterns
}

// InScope checks if a URL is within the defined scope.
func (t *Target) InScope(checkURL string) bool {
	parsed, err := url.Parse(checkURL)
	if err != nil {
		return false
	}

	checkDomain := parsed.Hostname()

	// Always allow the target's own domain
	if checkDomain == t.Domain() {
		return true
	}

	// Check against scope patterns
	for _, pattern := range t.scope {
		if matchesPattern(pattern, checkDomain) {
			return true
		}
	}

	return false
}

// matchesPattern checks if a domain matches a pattern (supports * wildcard).
func matchesPattern(pattern, domain string) bool {
	if strings.HasPrefix(pattern, "*.") {
		// Wildcard subdomain pattern
		suffix := pattern[1:] // Remove *
		return strings.HasSuffix(domain, suffix) || domain == pattern[2:]
	}
	return pattern == domain
}

// EntryPoint represents an entry point for security testing.
type EntryPoint struct {
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Parameters  []Parameter       `json:"parameters"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
}

// NewEntryPoint creates a new entry point.
func NewEntryPoint(url, method string) *EntryPoint {
	return &EntryPoint{
		URL:        url,
		Method:     method,
		Parameters: make([]Parameter, 0),
		Headers:    make(map[string]string),
	}
}

// AddParameter adds a parameter to the entry point.
func (e *EntryPoint) AddParameter(name, location, value string) {
	e.Parameters = append(e.Parameters, Parameter{
		Name:     name,
		Location: location,
		Value:    value,
	})
}

// HasParameter checks if a parameter exists.
func (e *EntryPoint) HasParameter(name string) bool {
	for _, p := range e.Parameters {
		if p.Name == name {
			return true
		}
	}
	return false
}

// GetParametersByLocation returns parameters by their location.
func (e *EntryPoint) GetParametersByLocation(location string) []Parameter {
	result := make([]Parameter, 0)
	for _, p := range e.Parameters {
		if p.Location == location {
			result = append(result, p)
		}
	}
	return result
}

// Parameter represents an input parameter.
type Parameter struct {
	Name           string `json:"name"`
	Location       string `json:"location"` // query, body, header, cookie, path
	Value          string `json:"value"`
	Type           string `json:"type,omitempty"`           // string, number, boolean, array, object
	Reflected      bool   `json:"reflected,omitempty"`      // whether value is reflected in response
	Classification string `json:"classification,omitempty"` // detected category (id, file, url, search, command, template, generic)
	ContentType    string `json:"content_type,omitempty"`   // response content type when this param was probed
	SegmentIndex   int    `json:"segment_index,omitempty"`  // for path params, the segment position
}

// Parameter classification constants.
const (
	ParamClassID       = "id"
	ParamClassFile     = "file"
	ParamClassURL      = "url"
	ParamClassSearch   = "search"
	ParamClassCommand  = "command"
	ParamClassTemplate = "template"
	ParamClassGeneric  = "generic"
)

// vulnerableExactNames contains parameter names that suggest vulnerability.
var vulnerableExactNames = map[string]bool{
	"id": true, "file": true, "path": true, "url": true, "uri": true, "src": true, "href": true,
	"redirect": true, "callback": true, "return": true, "next": true, "dest": true, "target": true,
	"query": true, "search": true, "q": true, "cmd": true, "exec": true, "command": true,
	"template": true, "include": true, "doc": true, "document": true,
}

// vulnerableSubstrings contains substrings that suggest vulnerability.
var vulnerableSubstrings = []string{
	"user", "file", "path", "url", "_id",
}

// IsPotentiallyVulnerable checks if the parameter name or classification suggests vulnerability.
func (p *Parameter) IsPotentiallyVulnerable() bool {
	// Classification-based check takes precedence when set
	if p.Classification != "" {
		return p.Classification != ParamClassGeneric
	}

	nameLower := strings.ToLower(p.Name)

	if vulnerableExactNames[nameLower] {
		return true
	}

	for _, pattern := range vulnerableSubstrings {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}

	return false
}

// classificationExactNames maps exact parameter names to classifications.
var classificationExactNames = map[string]string{
	"id": ParamClassID, "uid": ParamClassID, "pid": ParamClassID,
	"file": ParamClassFile, "document": ParamClassFile, "doc": ParamClassFile,
	"include": ParamClassFile, "page": ParamClassGeneric, "dir": ParamClassFile,
	"url": ParamClassURL, "uri": ParamClassURL, "redirect": ParamClassURL,
	"callback": ParamClassURL, "return": ParamClassURL, "next": ParamClassURL,
	"dest": ParamClassURL, "target": ParamClassURL, "href": ParamClassURL,
	"src": ParamClassURL, "link": ParamClassURL,
	"query": ParamClassSearch, "search": ParamClassSearch, "q": ParamClassSearch,
	"keyword": ParamClassSearch, "term": ParamClassSearch,
	"cmd": ParamClassCommand, "exec": ParamClassCommand, "command": ParamClassCommand,
	"run": ParamClassCommand, "execute": ParamClassCommand,
	"template": ParamClassTemplate, "tpl": ParamClassTemplate, "view": ParamClassTemplate,
}

// classificationSubstrings maps substrings to classifications.
var classificationSubstrings = []struct {
	substr string
	class  string
}{
	{"_id", ParamClassID},
	{"Id", ParamClassID},
	{"file", ParamClassFile},
	{"path", ParamClassFile},
	{"fname", ParamClassFile},
	{"redirect", ParamClassURL},
	{"url", ParamClassURL},
}

// Classify sets the Classification field based on parameter name heuristics.
func (p *Parameter) Classify() {
	nameLower := strings.ToLower(p.Name)

	if class, ok := classificationExactNames[nameLower]; ok {
		p.Classification = class
		return
	}

	for _, entry := range classificationSubstrings {
		if strings.Contains(p.Name, entry.substr) || strings.Contains(nameLower, strings.ToLower(entry.substr)) {
			p.Classification = entry.class
			return
		}
	}

	p.Classification = ParamClassGeneric
}

// ParameterLocation constants.
const (
	ParamLocationQuery          = "query"
	ParamLocationBody           = "body"
	ParamLocationHeader         = "header"
	ParamLocationCookie         = "cookie"
	ParamLocationPath           = "path"
	ParamLocationLocalStorage   = "localstorage"
	ParamLocationSessionStorage = "sessionstorage"
)

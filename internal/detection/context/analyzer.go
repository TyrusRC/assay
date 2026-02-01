package context

import (
	"encoding/base64"
	"encoding/json"
	"html"
	"net/url"
	"regexp"
	"strings"
)

// ParameterType represents the detected type of a parameter value.
type ParameterType int

const (
	TypeUnknown ParameterType = iota
	TypeString
	TypeNumeric
	TypeBoolean
	TypeEmail
	TypeURL
	TypePath
	TypeJSON
	TypeBase64
	TypeUUID
	TypeDate
)

// String returns the string representation of ParameterType.
func (t ParameterType) String() string {
	switch t {
	case TypeString:
		return "string"
	case TypeNumeric:
		return "numeric"
	case TypeBoolean:
		return "boolean"
	case TypeEmail:
		return "email"
	case TypeURL:
		return "url"
	case TypePath:
		return "path"
	case TypeJSON:
		return "json"
	case TypeBase64:
		return "base64"
	case TypeUUID:
		return "uuid"
	case TypeDate:
		return "date"
	default:
		return "unknown"
	}
}

// ReflectionContext represents where input is reflected in the response.
type ReflectionContext int

const (
	ContextNone ReflectionContext = iota
	ContextHTMLBody
	ContextHTMLAttribute
	ContextJavaScript
	ContextURL
	ContextCSS
	ContextJSON
)

// String returns the string representation of ReflectionContext.
func (c ReflectionContext) String() string {
	switch c {
	case ContextHTMLBody:
		return "html_body"
	case ContextHTMLAttribute:
		return "html_attribute"
	case ContextJavaScript:
		return "javascript"
	case ContextURL:
		return "url"
	case ContextCSS:
		return "css"
	case ContextJSON:
		return "json"
	default:
		return "none"
	}
}

// AnalysisResult contains the result of parameter analysis.
type AnalysisResult struct {
	Type       ParameterType
	Confidence float64
	Patterns   []string
}

// ReflectionResult contains the result of reflection analysis.
type ReflectionResult struct {
	IsReflected bool
	Encoding    string
	Context     ReflectionContext
	Position    int
}

// Pre-compiled regexes for response context analysis.
var (
	urlAttrContextRe  = regexp.MustCompile(`(?i)(href|src|action)\s*=\s*["'][^"']*$`)
	htmlAttrContextRe = regexp.MustCompile(`<[^>]+\s+\w+\s*=\s*["'][^"']*$`)
)

// Analyzer performs context-aware analysis of parameters and responses.
type Analyzer struct {
	// Compiled regex patterns
	numericPattern *regexp.Regexp
	emailPattern   *regexp.Regexp
	urlPattern     *regexp.Regexp
	pathPattern    *regexp.Regexp
	uuidPattern    *regexp.Regexp
	datePattern    *regexp.Regexp
	base64Pattern  *regexp.Regexp
	booleanNames   map[string]bool
}

// NewAnalyzer creates a new context analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		numericPattern: regexp.MustCompile(`^-?\d+(\.\d+)?$`),
		emailPattern:   regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`),
		urlPattern:     regexp.MustCompile(`^(https?|ftp)://[^\s/$.?#].[^\s]*$`),
		pathPattern:    regexp.MustCompile(`^(/[^/\s]+)+/?$|^[A-Za-z]:\\`),
		uuidPattern:    regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`),
		datePattern:    regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`),
		base64Pattern:  regexp.MustCompile(`^[A-Za-z0-9+/]+=*$`),
		booleanNames: map[string]bool{
			"active": true, "enabled": true, "disabled": true, "flag": true,
			"checked": true, "selected": true, "visible": true, "hidden": true,
			"public": true, "private": true, "confirmed": true, "verified": true,
		},
	}
}

// AnalyzeParameter analyzes a parameter name and value to determine its type.
func (a *Analyzer) AnalyzeParameter(name, value string) *AnalysisResult {
	result := &AnalysisResult{
		Type:       TypeUnknown,
		Confidence: 0.0,
		Patterns:   make([]string, 0),
	}

	if value == "" {
		return result
	}

	// Check for specific types in order of specificity
	if a.isJSON(value) {
		result.Type = TypeJSON
		result.Confidence = 0.95
		result.Patterns = append(result.Patterns, "json")
		return result
	}

	if a.uuidPattern.MatchString(value) {
		result.Type = TypeUUID
		result.Confidence = 0.99
		result.Patterns = append(result.Patterns, "uuid")
		return result
	}

	if a.emailPattern.MatchString(value) {
		result.Type = TypeEmail
		result.Confidence = 0.95
		result.Patterns = append(result.Patterns, "email")
		return result
	}

	if a.urlPattern.MatchString(value) {
		result.Type = TypeURL
		result.Confidence = 0.95
		result.Patterns = append(result.Patterns, "url")
		return result
	}

	if a.pathPattern.MatchString(value) {
		result.Type = TypePath
		result.Confidence = 0.85
		result.Patterns = append(result.Patterns, "path")
		return result
	}

	if a.datePattern.MatchString(value) {
		result.Type = TypeDate
		result.Confidence = 0.90
		result.Patterns = append(result.Patterns, "date")
		return result
	}

	// Check boolean values
	valueLower := strings.ToLower(value)
	if valueLower == "true" || valueLower == "false" {
		result.Type = TypeBoolean
		result.Confidence = 0.95
		result.Patterns = append(result.Patterns, "boolean")
		return result
	}

	// Check for boolean based on parameter name and value
	nameLower := strings.ToLower(name)
	if a.booleanNames[nameLower] && (value == "0" || value == "1") {
		result.Type = TypeBoolean
		result.Confidence = 0.80
		result.Patterns = append(result.Patterns, "boolean_flag")
		return result
	}

	// Check base64 (must be long enough and have valid chars)
	if len(value) >= 8 && a.base64Pattern.MatchString(value) && a.isValidBase64(value) {
		result.Type = TypeBase64
		result.Confidence = 0.75
		result.Patterns = append(result.Patterns, "base64")
		return result
	}

	// Check numeric
	if a.numericPattern.MatchString(value) {
		result.Type = TypeNumeric
		result.Confidence = 0.95
		result.Patterns = append(result.Patterns, "numeric")
		return result
	}

	// Default to string
	result.Type = TypeString
	result.Confidence = 0.70
	result.Patterns = append(result.Patterns, "alphanumeric")
	return result
}

// isJSON checks if a value is valid JSON.
func (a *Analyzer) isJSON(value string) bool {
	value = strings.TrimSpace(value)
	if (strings.HasPrefix(value, "{") && strings.HasSuffix(value, "}")) ||
		(strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]")) {
		var js interface{}
		return json.Unmarshal([]byte(value), &js) == nil
	}
	return false
}

// isValidBase64 checks if a value decodes as valid base64.
func (a *Analyzer) isValidBase64(value string) bool {
	_, err := base64.StdEncoding.DecodeString(value)
	return err == nil
}

// DetectReflection checks if input is reflected in the response.
func (a *Analyzer) DetectReflection(input, response string) *ReflectionResult {
	result := &ReflectionResult{
		IsReflected: false,
		Context:     ContextNone,
	}

	if input == "" || response == "" {
		return result
	}

	// Check for exact match
	if strings.Contains(response, input) {
		result.IsReflected = true
		result.Encoding = "none"
		result.Position = strings.Index(response, input)
		return result
	}

	// Check for HTML encoded
	htmlEncoded := html.EscapeString(input)
	if htmlEncoded != input && strings.Contains(response, htmlEncoded) {
		result.IsReflected = true
		result.Encoding = "html"
		result.Position = strings.Index(response, htmlEncoded)
		return result
	}

	// Check for URL encoded (both + and %20 for spaces)
	urlEncoded := url.QueryEscape(input)
	if urlEncoded != input && strings.Contains(response, urlEncoded) {
		result.IsReflected = true
		result.Encoding = "url"
		result.Position = strings.Index(response, urlEncoded)
		return result
	}

	// Check for path-style URL encoding (%20 instead of +)
	urlPathEncoded := url.PathEscape(input)
	if urlPathEncoded != input && strings.Contains(response, urlPathEncoded) {
		result.IsReflected = true
		result.Encoding = "url"
		result.Position = strings.Index(response, urlPathEncoded)
		return result
	}

	// Check case-insensitive
	if strings.Contains(strings.ToLower(response), strings.ToLower(input)) {
		result.IsReflected = true
		result.Encoding = "case_modified"
		return result
	}

	return result
}

// AnalyzeResponseContext determines where input is reflected in the response.
func (a *Analyzer) AnalyzeResponseContext(input, response string) *ReflectionResult {
	result := &ReflectionResult{
		IsReflected: false,
		Context:     ContextNone,
	}

	if !strings.Contains(response, input) {
		return result
	}

	result.IsReflected = true
	pos := strings.Index(response, input)

	// Get surrounding context
	start := pos - 100
	if start < 0 {
		start = 0
	}
	end := pos + len(input) + 100
	if end > len(response) {
		end = len(response)
	}
	context := response[start:end]
	beforeInput := response[start:pos]

	// Check for JSON context first (simple check)
	if strings.HasPrefix(strings.TrimSpace(response), "{") || strings.HasPrefix(strings.TrimSpace(response), "[") {
		result.Context = ContextJSON
		return result
	}

	// Check JavaScript context
	if strings.Contains(beforeInput, "<script") && !strings.Contains(beforeInput, "</script>") {
		result.Context = ContextJavaScript
		return result
	}

	// Check CSS context
	if strings.Contains(beforeInput, "<style") && !strings.Contains(beforeInput, "</style>") {
		result.Context = ContextCSS
		return result
	}

	// Check URL context (in href or src attributes)
	if urlAttrContextRe.MatchString(beforeInput) {
		result.Context = ContextURL
		return result
	}

	// Check HTML attribute context
	if htmlAttrContextRe.MatchString(beforeInput) {
		result.Context = ContextHTMLAttribute
		return result
	}

	// Check if inside HTML tags (but not in attribute)
	if strings.Contains(context, "<") && strings.Contains(context, ">") {
		result.Context = ContextHTMLBody
		return result
	}

	result.Context = ContextHTMLBody
	return result
}

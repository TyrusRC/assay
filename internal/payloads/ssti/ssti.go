// Package ssti provides Server-Side Template Injection payloads for various template engines.
// Payloads are categorized by:
//   - Template engine (Jinja2, Twig, Freemarker, Velocity, ERB, Thymeleaf, Mako)
//   - Type (Detection, Fingerprint, RCE)
//   - Detection mechanism (Mathematical expression, Error-based, Config leak)
package ssti

// TemplateEngine represents the type of template engine.
type TemplateEngine string

const (
	// EngineJinja2 represents Python Jinja2/Flask template engine.
	EngineJinja2 TemplateEngine = "jinja2"
	// EngineTwig represents PHP Twig template engine.
	EngineTwig TemplateEngine = "twig"
	// EngineFreemarker represents Java Freemarker template engine.
	EngineFreemarker TemplateEngine = "freemarker"
	// EngineVelocity represents Java Velocity template engine.
	EngineVelocity TemplateEngine = "velocity"
	// EngineERB represents Ruby ERB template engine.
	EngineERB TemplateEngine = "erb"
	// EngineThymeleaf represents Java Thymeleaf template engine.
	EngineThymeleaf TemplateEngine = "thymeleaf"
	// EngineMako represents Python Mako template engine.
	EngineMako TemplateEngine = "mako"
	// EngineSmarty represents PHP Smarty template engine.
	EngineSmarty TemplateEngine = "smarty"
	// EnginePebble represents Java Pebble template engine.
	EnginePebble TemplateEngine = "pebble"
	// EngineHandlebars represents JavaScript Handlebars template engine.
	EngineHandlebars TemplateEngine = "handlebars"
	// EngineMustache represents Mustache template engine.
	EngineMustache TemplateEngine = "mustache"
	// EngineUnknown represents an unknown template engine.
	EngineUnknown TemplateEngine = "unknown"
)

// PayloadType represents the purpose of the payload.
type PayloadType string

const (
	// TypeDetection is for initial vulnerability detection.
	TypeDetection PayloadType = "detection"
	// TypeFingerprint is for identifying the template engine.
	TypeFingerprint PayloadType = "fingerprint"
	// TypeRCE is for Remote Code Execution verification.
	TypeRCE PayloadType = "rce"
	// TypeConfigLeak is for configuration/secret leakage.
	TypeConfigLeak PayloadType = "config_leak"
	// TypeFileRead is for local file read.
	TypeFileRead PayloadType = "file_read"
)

// DetectionMethod represents how to verify if the payload worked.
type DetectionMethod string

const (
	// MethodMath detects by checking for mathematical result (e.g., 49 from 7*7).
	MethodMath DetectionMethod = "math"
	// MethodError detects by checking for error messages.
	MethodError DetectionMethod = "error"
	// MethodReflection detects by checking for reflected content.
	MethodReflection DetectionMethod = "reflection"
	// MethodOutput detects by checking for specific command output.
	MethodOutput DetectionMethod = "output"
)

// Payload represents an SSTI payload.
type Payload struct {
	Value           string         // The payload string to inject
	Engine          TemplateEngine // Target template engine
	Type            PayloadType    // Purpose of the payload
	Description     string         // Human-readable description
	DetectionMethod DetectionMethod
	ExpectedOutput  string // Expected output to look for (e.g., "49" for 7*7)
	ErrorPatterns   []string
	WAFBypass       bool // Designed to evade WAF
}

// GetPayloads returns payloads for a specific template engine.
func GetPayloads(engine TemplateEngine) []Payload {
	switch engine {
	case EngineJinja2:
		return jinja2Payloads
	case EngineTwig:
		return twigPayloads
	case EngineFreemarker:
		return freemarkerPayloads
	case EngineVelocity:
		return velocityPayloads
	case EngineERB:
		return erbPayloads
	case EngineThymeleaf:
		return thymeleafPayloads
	case EngineMako:
		return makoPayloads
	case EngineSmarty:
		return smartyPayloads
	case EnginePebble:
		return pebblePayloads
	case EngineHandlebars:
		return handlebarsPayloads
	case EngineMustache:
		return mustachePayloads
	default:
		return GetAllPayloads()
	}
}

// GetDetectionPayloads returns payloads specifically for initial detection.
func GetDetectionPayloads() []Payload {
	var result []Payload
	for _, p := range GetAllPayloads() {
		if p.Type == TypeDetection || p.Type == TypeFingerprint {
			result = append(result, p)
		}
	}
	return result
}

// GetRCEPayloads returns payloads for RCE verification.
func GetRCEPayloads() []Payload {
	var result []Payload
	for _, p := range GetAllPayloads() {
		if p.Type == TypeRCE {
			result = append(result, p)
		}
	}
	return result
}

// GetMathPayloads returns payloads that use mathematical expressions for detection.
func GetMathPayloads() []Payload {
	var result []Payload
	for _, p := range GetAllPayloads() {
		if p.DetectionMethod == MethodMath {
			result = append(result, p)
		}
	}
	return result
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

// GetFingerprintPayloads returns payloads for engine fingerprinting.
func GetFingerprintPayloads() []Payload {
	var result []Payload
	for _, p := range GetAllPayloads() {
		if p.Type == TypeFingerprint {
			result = append(result, p)
		}
	}
	return result
}

// GetAllPayloads returns all SSTI payloads.
func GetAllPayloads() []Payload {
	var all []Payload
	all = append(all, jinja2Payloads...)
	all = append(all, twigPayloads...)
	all = append(all, freemarkerPayloads...)
	all = append(all, velocityPayloads...)
	all = append(all, erbPayloads...)
	all = append(all, thymeleafPayloads...)
	all = append(all, makoPayloads...)
	all = append(all, smartyPayloads...)
	all = append(all, pebblePayloads...)
	all = append(all, handlebarsPayloads...)
	all = append(all, mustachePayloads...)
	all = append(all, polyglotPayloads...)
	return all
}

// GetPolyglotPayloads returns payloads that work across multiple engines.
func GetPolyglotPayloads() []Payload {
	return polyglotPayloads
}

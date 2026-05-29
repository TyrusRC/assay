// Package vhost provides hostname wordlists for VirtualHost enumeration —
// finding internal/staging/admin sites that share an IP with the public
// site but require a specific `Host:` header to reach. Mirrors AWVS
// VirtualHost_Audit.script.
//
// The scanner rotates each generated FQDN through the `Host:` header
// against the target IP and looks for a response differential
// (non-default body, different Content-Length, different Server header)
// indicating the host is served from a distinct vhost block.
//
// Wordlist sourced from SecLists DNS short-names + common SaaS/internal
// service names (Jenkins, Grafana, Kibana, Prometheus, …).
package vhost

import "strings"

// CommonHostnames returns the canonical short-name wordlist (no domain
// suffix). Use GenerateVHosts(domain) to materialise full FQDNs.
func CommonHostnames() []string {
	return []string{
		// admin / management
		"admin", "administrator", "manage", "manager", "console", "panel",
		"dashboard", "backoffice", "backend",
		// environments
		"dev", "develop", "development", "test", "testing", "staging",
		"stage", "qa", "preprod", "uat", "sandbox", "preview",
		"prod", "production",
		// API surfaces
		"api", "api-v1", "api-v2", "api-v3", "graphql", "rest", "rpc",
		// internal/intranet
		"internal", "intranet", "extranet", "private", "secret",
		// dev infra
		"jenkins", "gitlab", "git", "gitea", "bitbucket",
		"jira", "confluence", "wiki", "docs",
		"nexus", "artifactory", "registry",
		// monitoring
		"grafana", "kibana", "prometheus", "alertmanager", "victoria",
		"zabbix", "nagios", "datadog", "sentry", "newrelic",
		// CI/CD
		"ci", "cd", "build", "deploy", "release",
		// services
		"mail", "smtp", "imap", "pop", "webmail",
		"ftp", "sftp", "ssh", "vpn", "remote",
		// storage
		"storage", "files", "fileshare", "nas", "s3", "minio",
		// auth
		"auth", "sso", "login", "oauth", "idp", "keycloak", "okta",
		// network plumbing
		"proxy", "lb", "loadbalancer", "router", "firewall",
		// db / data
		"db", "database", "mysql", "postgres", "mongo", "redis", "elasticsearch",
		// metadata
		"metadata", "config", "health", "status", "metrics",
		// other common
		"old", "new", "beta", "alpha", "demo",
		"www", "www2", "web", "site",
		"support", "help", "kb",
	}
}

// EnvironmentPrefixes returns the env-tier prefixes that get concatenated
// with common hostnames to form variants like `staging-admin`, `dev-api`.
func EnvironmentPrefixes() []string {
	return []string{"dev", "develop", "staging", "stage", "test", "qa", "prod", "production", "uat", "preprod", "sandbox"}
}

// GenerateVHosts returns a deduplicated FQDN list for the supplied domain,
// combining bare hostnames and `<prefix>-<host>` permutations.
func GenerateVHosts(domain string) []string {
	d := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(domain), "."))
	if d == "" {
		return nil
	}
	seen := make(map[string]bool, 256)
	var out []string

	add := func(name string) {
		fqdn := name + "." + d
		if !seen[fqdn] {
			seen[fqdn] = true
			out = append(out, fqdn)
		}
	}

	hostnames := CommonHostnames()
	for _, h := range hostnames {
		add(h)
	}
	for _, env := range EnvironmentPrefixes() {
		for _, h := range hostnames {
			if env == h {
				// Avoid silly `dev-dev.example.com` etc.
				continue
			}
			add(env + "-" + h)
			add(env + h) // no-separator variant (devadmin, stagingapi)
		}
	}
	return out
}

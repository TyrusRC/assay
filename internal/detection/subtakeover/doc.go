// Package subtakeover provides detection for subdomain takeover vulnerabilities.
//
// Subdomain takeover occurs when a DNS record (typically a CNAME) points to
// an external service that has been deprovisioned, allowing an attacker to
// claim the service and serve content under the target's subdomain.
//
// Detection techniques:
//   - CNAME record analysis for dangling references
//   - Service fingerprint matching against known vulnerable providers
//   - HTTP response verification for unclaimed resource indicators
//
// OWASP mappings:
//   - WSTG-CONF-10 (Test for Subdomain Takeover)
//   - A05:2021 (Security Misconfiguration)
//   - CWE-284 (Improper Access Control)
package subtakeover

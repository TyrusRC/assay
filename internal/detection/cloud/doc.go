// Package cloud provides detection for cloud storage misconfiguration vulnerabilities.
//
// The detector identifies publicly accessible cloud storage buckets and
// misconfigured access controls across major cloud providers. It tests
// for unauthorized read, write, and listing permissions on storage resources.
//
// Detection techniques:
//   - Public bucket enumeration and access testing
//   - Misconfigured ACL and policy detection
//   - Cross-provider storage analysis
//
// OWASP mappings:
//   - WSTG-CONF-11 (Test Cloud Storage)
//   - A05:2021 (Security Misconfiguration)
//   - CWE-284 (Improper Access Control)
//   - CWE-732 (Incorrect Permission Assignment for Critical Resource)
package cloud

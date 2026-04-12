// Package cachepoisoning provides web cache poisoning vulnerability detection.
//
// The detector identifies cache poisoning vulnerabilities by sending unkeyed
// headers with unique values and checking if cached responses contain them,
// indicating that the cache key does not include those header values.
//
// Tested headers:
//   - X-Forwarded-Host (host reflection in links and redirects)
//   - X-Forwarded-Scheme (scheme confusion causing redirect loops)
//   - X-Original-URL (path override bypassing access controls)
//   - X-Forwarded-Port (port injection in generated URLs)
//
// Detection techniques:
//   - Header value reflection analysis
//   - Response differential comparison
//   - Status code change detection (redirects)
//   - Cache header analysis
//
// OWASP mappings:
//   - WSTG-INPV-17 (Testing for HTTP Request Smuggling)
//   - A05:2021 (Security Misconfiguration)
//   - CWE-444 (Inconsistent Interpretation of HTTP Requests)
package cachepoisoning

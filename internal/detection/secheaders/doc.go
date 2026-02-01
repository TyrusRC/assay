// Package secheaders provides detection for HTTP security header misconfigurations.
//
// The detector analyzes HTTP response headers to identify missing, misconfigured,
// or weak security headers that leave applications vulnerable to common
// client-side attacks and information disclosure.
//
// Headers analyzed:
//   - Strict-Transport-Security (HSTS) with max-age validation
//   - Content-Security-Policy (CSP)
//   - X-Content-Type-Options
//   - X-Frame-Options
//   - X-XSS-Protection
//   - Referrer-Policy
//   - Permissions-Policy
//   - Information disclosure headers (Server, X-Powered-By)
//
// OWASP mappings:
//   - WSTG-CONF-05 (Enumerate Infrastructure and Application Admin Interfaces)
//   - WSTG-INFO-02 (Fingerprint Web Server)
//   - A05:2021 (Security Misconfiguration)
package secheaders

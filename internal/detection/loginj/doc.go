// Package loginj provides log injection vulnerability detection.
//
// The detector identifies log injection vulnerabilities by sending CRLF
// sequences, format string specifiers, and fake log entries through commonly
// logged HTTP headers and checking if the payloads are reflected in responses.
//
// Injection vectors:
//   - User-Agent header (commonly logged by web servers)
//   - Referer header (logged for analytics and error tracking)
//   - X-Forwarded-For header (logged for client IP tracking)
//
// Detection techniques:
//   - CRLF injection in response headers and body
//   - Format string specifier reflection
//   - Fake log entry injection
//   - Log4j JNDI lookup detection
//
// OWASP mappings:
//   - WSTG-INPV-14 (Testing for Log Injection)
//   - A09:2021 (Security Logging and Monitoring Failures)
//   - CWE-117 (Improper Output Neutralization for Logs)
package loginj

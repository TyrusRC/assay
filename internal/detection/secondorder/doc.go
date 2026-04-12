// Package secondorder provides detection for second-order and blind injection vulnerabilities.
//
// Second-order attacks inject payloads that trigger when the data is used in a different
// context, such as when stored input is rendered in an admin panel, included in a report,
// or processed by a backend system. These vulnerabilities are particularly dangerous because
// they may bypass input validation that only inspects immediate responses.
//
// Detection strategies:
//   - BlindXSS: Inject XSS payloads in headers and form fields that trigger in admin views.
//   - SecondOrderSQLi: Inject SQL payloads via registration/profile, trigger in reports.
//   - LogInjection: Inject CRLF and format strings in logged headers.
//   - JNDIHeaders: Inject JNDI lookups in injectable headers for Log4Shell detection.
//
// OWASP mappings:
//   - WSTG-INPV-02 (Testing for Stored Cross-Site Scripting)
//   - WSTG-INPV-05 (Testing for SQL Injection)
//   - WSTG-INPV-07 (Testing for Log Injection)
//   - A03:2021 (Injection)
//   - CWE-79 (Cross-Site Scripting)
//   - CWE-89 (SQL Injection)
//   - CWE-117 (Improper Output Neutralization for Logs)
//   - CWE-917 (Expression Language Injection)
package secondorder

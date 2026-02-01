// Package jndi provides detection for Log4Shell/JNDI Injection vulnerabilities.
//
// JNDI injection, most notably exploited via Log4Shell (CVE-2021-44228),
// allows attackers to execute arbitrary code by injecting JNDI lookup
// strings into logged data. The detector tests HTTP headers, query
// parameters, and request bodies for JNDI lookup processing.
//
// Detection techniques:
//   - Out-of-band callback detection via JNDI/LDAP/RMI lookups
//   - Header-based injection (User-Agent, Referer, X-Forwarded-For, etc.)
//   - Parameter-based injection via query strings and POST bodies
//   - WAF bypass techniques using obfuscated lookup strings
//
// OWASP mappings:
//   - WSTG-INPV-11 (Testing for Code Injection)
//   - A06:2021 (Vulnerable and Outdated Components)
//   - CWE-917 (Improper Neutralization of Special Elements Used in an Expression Language Statement)
//   - CWE-502 (Deserialization of Untrusted Data)
package jndi

// Package ldap provides detection for LDAP Injection vulnerabilities.
//
// LDAP injection occurs when user input is incorporated into LDAP queries
// without proper sanitization, allowing attackers to modify query logic
// to bypass authentication or access unauthorized directory entries.
//
// Detection techniques:
//   - Error-based detection via malformed LDAP filter syntax
//   - Boolean-based detection using tautology and contradiction filters
//   - Response differential analysis
//   - WAF bypass techniques for filtered inputs
//
// OWASP mappings:
//   - WSTG-INPV-06 (Testing for LDAP Injection)
//   - A03:2021 (Injection)
//   - CWE-90 (Improper Neutralization of Special Elements Used in an LDAP Query)
package ldap

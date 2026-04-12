// Package hpp provides detection for HTTP Parameter Pollution vulnerabilities.
//
// HTTP Parameter Pollution (HPP) occurs when an application accepts multiple
// HTTP parameters with the same name, and the backend framework handles the
// duplicates in an unexpected or insecure way. Attackers can exploit this to
// bypass input validation, override parameter values, or cause unintended
// application behavior.
//
// Detection techniques:
//   - Duplicate parameter injection with different values
//   - Array-style parameter injection (param[]=x)
//   - Encoded parameter variants
//   - Response differential analysis between baseline and injected requests
//
// OWASP mappings:
//   - WSTG-INPV-04 (Testing for HTTP Parameter Pollution)
//   - A03:2021 (Injection)
//   - CWE-235 (Improper Handling of Extra Parameters)
package hpp

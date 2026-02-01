// Package csti provides detection for Client-Side Template Injection vulnerabilities.
//
// CSTI occurs when user input is embedded into client-side template engines
// (such as AngularJS, Vue.js, or React) without proper sanitization, allowing
// attackers to execute arbitrary JavaScript in the victim's browser.
//
// Detection techniques:
//   - Mathematical expression evaluation (e.g., {{7*7}} resolving to 49)
//   - Framework-specific payload testing
//   - WAF bypass techniques for filtered inputs
//
// OWASP mappings:
//   - WSTG-CLNT-11 (Testing for Client-side Template Injection)
//   - A03:2021 (Injection)
//   - CWE-79 (Improper Neutralization of Input During Web Page Generation)
package csti

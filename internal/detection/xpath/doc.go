// Package xpath provides detection for XPath Injection vulnerabilities.
//
// XPath injection occurs when user input is incorporated into XPath queries
// without proper sanitization, allowing attackers to manipulate query logic
// to extract data from XML documents or bypass authentication controls.
//
// Detection techniques:
//   - Error-based detection via malformed XPath expressions
//   - Boolean-based detection using tautology and contradiction queries
//   - Response differential analysis
//   - WAF bypass techniques for filtered inputs
//
// OWASP mappings:
//   - WSTG-INPV-09 (Testing for XPath Injection)
//   - A03:2021 (Injection)
//   - CWE-643 (Improper Neutralization of Data Within XPath Expressions)
package xpath

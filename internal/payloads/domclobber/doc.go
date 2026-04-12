// Package domclobber provides DOM Clobbering payloads for client-side
// vulnerability detection.
//
// DOM Clobbering exploits the behavior of browsers that automatically
// create global variables from elements with name or id attributes,
// which can override existing DOM properties and APIs.
//
// Payloads are categorized by HTML element type:
//   - form (id attribute creates named property)
//   - img (name attribute creates named property)
//   - anchor (id and name create overlapping references)
//   - object (creates browsing context references)
//   - embed (creates plugin context references)
//
// OWASP mappings:
//   - WSTG-CLNT-06 (Testing for Client-side Resource Manipulation)
//   - CWE-79 (Improper Neutralization of Input During Web Page Generation)
package domclobber

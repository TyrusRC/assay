// Package domclobber provides DOM Clobbering vulnerability detection.
//
// The detector identifies DOM clobbering vulnerabilities by injecting
// named HTML elements (forms, images, anchors with name/id attributes)
// and checking if they appear unencoded in the response, which would
// allow client-side property overrides.
//
// Detection techniques:
//   - Inject named form, img, anchor, object, and embed elements
//   - Check if injected elements appear raw (unencoded) in response
//   - Verify the element tags and their id/name attributes are preserved
//
// OWASP mappings:
//   - WSTG-CLNT-06 (Testing for Client-side Resource Manipulation)
//   - A03:2021 (Injection)
//   - CWE-79 (Improper Neutralization of Input During Web Page Generation)
package domclobber

// Package protopollution provides Prototype Pollution vulnerability detection.
//
// The detector identifies prototype pollution vulnerabilities by injecting
// payloads via query parameters and JSON bodies, then checking if the
// response indicates the prototype was modified.
//
// Detection techniques:
//   - Query parameter injection (__proto__[key]=value)
//   - JSON body injection ({"__proto__": {"key": "value"}})
//   - Dot notation injection (__proto__.key=value)
//   - Error message analysis for prototype-related errors
//   - Response differential analysis for injected markers
//
// OWASP mappings:
//   - WSTG-CLNT-06 (Testing for Client-side Resource Manipulation)
//   - A03:2021 (Injection)
//   - CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)
package protopollution

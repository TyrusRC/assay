// Package protopollution provides Prototype Pollution payloads for
// client-side and server-side JavaScript vulnerability detection.
//
// Payloads are categorized by injection technique:
//   - Query parameter injection (__proto__[key]=value)
//   - JSON body injection ({"__proto__": {"key": "value"}})
//   - Dot notation injection (__proto__.key=value)
//
// OWASP mappings:
//   - WSTG-CLNT-06 (Testing for Client-side Resource Manipulation)
//   - CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)
package protopollution

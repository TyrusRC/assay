// Package injection provides detection capabilities for injection vulnerabilities
// including SQL injection, command injection, and other injection-based attacks.
//
// This package implements context-aware detection that identifies the parameter
// context (string, numeric, etc.) to optimize payload selection and reduce
// false positives.
package injection

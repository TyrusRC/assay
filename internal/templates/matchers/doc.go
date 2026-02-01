// Package matchers provides response matching capabilities for nuclei-compatible
// security templates.
//
// The matcher engine evaluates conditions against HTTP, DNS, and network
// responses to determine whether a vulnerability signature is present.
// It supports multiple matching strategies that can be combined with
// AND/OR logic.
//
// Supported matcher types:
//   - Word matching (exact and case-insensitive substring search)
//   - Regex matching with named capture group extraction
//   - Status code matching for HTTP responses
//   - Binary matching for raw protocol analysis
//   - DSL expressions with built-in helper functions
//   - XPath matching for XML/HTML response analysis
//   - Time-based matching for blind detection techniques
//
// The DSL engine provides string manipulation, encoding, hashing, and
// comparison functions for writing advanced match conditions.
package matchers

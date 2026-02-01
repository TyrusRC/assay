// Package executor provides template execution capabilities for nuclei-compatible
// security templates.
//
// The executor takes parsed templates and runs them against target hosts,
// handling HTTP request construction, DNS queries, and raw network connections.
// It coordinates request sending, response matching, and data extraction
// across multiple protocol types.
//
// Supported protocols:
//   - HTTP (request building, redirect following, response analysis)
//   - DNS (query construction, record type handling, nameserver configuration)
//   - Network (raw TCP/TLS connections, binary protocol support)
//
// Features:
//   - Concurrent template execution with configurable parallelism
//   - Template variable interpolation
//   - Response data extraction via regex, JSON, and XPath
//   - Stop-at-first-match optimization
package executor

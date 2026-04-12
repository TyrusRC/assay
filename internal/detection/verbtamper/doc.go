// Package verbtamper provides HTTP Verb Tampering vulnerability detection.
// It uses multiple detection techniques including:
//   - Testing different HTTP methods (GET, POST, PUT, DELETE, PATCH, OPTIONS, TRACE, HEAD)
//   - Detecting authentication bypass via alternative HTTP verbs
//   - Testing X-HTTP-Method-Override and related headers
//   - Comparing response status codes and content lengths
package verbtamper

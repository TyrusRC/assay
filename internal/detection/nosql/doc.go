// Package nosql provides NoSQL injection vulnerability detection.
//
// The detector identifies injection vulnerabilities in applications that use
// NoSQL databases by testing for operator injection, JavaScript injection,
// and response-based anomalies across multiple database backends.
//
// Supported databases:
//   - MongoDB (operator injection, JavaScript execution)
//   - CouchDB (view injection, API exploitation)
//   - Elasticsearch (query DSL injection)
//   - Redis (command injection)
//
// Detection techniques:
//   - Operator injection ($gt, $ne, $regex, etc.)
//   - JavaScript code injection in server-side evaluation
//   - Error-based detection via database-specific error patterns
//   - Response differential analysis
//
// OWASP mappings:
//   - WSTG-INPV-05 (Testing for NoSQL Injection)
//   - A03:2021 (Injection)
//   - CWE-943 (Improper Neutralization of Special Elements in Data Query Logic)
package nosql

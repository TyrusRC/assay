// Package graphql provides comprehensive GraphQL API vulnerability detection.
//
// This package detects the following vulnerability classes as defined by OWASP:
//
// # Introspection Enabled
//
// GraphQL introspection allows clients to query the schema, exposing
// all available types, fields, queries, and mutations. This is a significant
// security risk in production as it reveals the entire API surface.
//
//	OWASP API: API3:2023 - Broken Object Property Level Authorization
//	CWE: CWE-200 (Information Exposure)
//
// # Batch Query Attacks
//
// GraphQL supports batching multiple queries in a single request, which can
// be abused for credential stuffing, brute force attacks, or DoS.
//
//	OWASP API: API4:2023 - Unrestricted Resource Consumption
//	CWE: CWE-770 (Allocation of Resources Without Limits)
//
// # Depth Limit Bypass
//
// Deeply nested queries can cause exponential data fetching and server
// resource exhaustion if depth limits are not enforced.
//
//	OWASP API: API4:2023 - Unrestricted Resource Consumption
//	CWE: CWE-400 (Uncontrolled Resource Consumption)
//
// # Field Suggestion Exploitation
//
// GraphQL field suggestions in error messages can leak schema information
// even when introspection is disabled.
//
//	OWASP API: API3:2023 - Broken Object Property Level Authorization
//	CWE: CWE-209 (Information Exposure Through Error Messages)
//
// # SQL/NoSQL Injection in Arguments
//
// GraphQL arguments may be vulnerable to injection attacks if resolvers
// don't properly sanitize input before database queries.
//
//	OWASP API: API8:2023 - Security Misconfiguration
//	CWE: CWE-89 (SQL Injection), CWE-943 (NoSQL Injection)
//
// # Authorization Bypass
//
// Improper authorization in GraphQL resolvers can allow unauthorized
// access to fields or mutations.
//
//	OWASP API: API1:2023 - Broken Object Level Authorization
//	CWE: CWE-862 (Missing Authorization)
//
// # Usage
//
// Basic usage:
//
//	client := http.NewClient()
//	detector := graphql.New(client)
//	opts := graphql.DefaultOptions()
//
//	result, err := detector.Detect(ctx, "https://api.example.com/graphql", opts)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	for _, finding := range result.Findings {
//	    fmt.Printf("Found: %s (Severity: %s)\n", finding.Type, finding.Severity)
//	}
//
// # Endpoint Discovery
//
// The package can discover GraphQL endpoints at common paths:
//
//	endpoints, err := detector.DiscoverEndpoints(ctx, "https://example.com")
//	for _, ep := range endpoints {
//	    fmt.Printf("Found GraphQL endpoint: %s\n", ep)
//	}
//
// # References
//
//   - OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
//   - OWASP API Security Top 10: https://owasp.org/API-Security/
//   - GraphQL Security: https://graphql.org/learn/security/
package graphql

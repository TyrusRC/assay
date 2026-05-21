// Package graphqladvanced probes a GraphQL endpoint for three classes
// of misconfiguration the existing internal/detection/graphql/ package
// does not cover: active field-suggestion schema recovery,
// Automatic-Persisted-Query (APQ) bypass, and mutation-over-GET CSRF.
//
// What graphql/ already does: passive detection that introspection is
// enabled, that field suggestions are returned, that batch queries are
// accepted, that depth-limit is bypassed, that aliases can be batched
// for credential brute force, and that arguments contain classic
// injection sinks.
//
// What graphqladvanced/ adds:
//
//   - field_suggestion_recovery — when introspection is disabled but
//     the server still emits "Did you mean ...?" suggestions, an
//     attacker can probe with deliberate typos and reconstruct the
//     schema field-by-field. Existing graphql/ flags that suggestions
//     are *enabled*; graphqladvanced/ demonstrates *recoverability*.
//
//   - apq_bypass — APQ relies on a SHA-256 hash to authorize a query;
//     servers that fall back to executing the supplied "query" string
//     when the hash isn't cached break the allowlist guarantee that
//     APQ is supposed to provide.
//
//   - get_mutation_csrf — GraphQL endpoints that accept mutations over
//     HTTP GET turn every mutation into a CSRF gadget. Detection: send
//     a synthetic mutation as a GET query parameter and observe whether
//     the server returns a non-error response.
//
// OWASP mappings:
//   - API3:2023 (Broken Object Property Level Authorization)
//   - API7:2023 (Server Side Request Forgery / CSRF surface)
//   - A01:2025 (Broken Access Control)
//   - CWE-200 (Information Exposure)
//   - CWE-352 (CSRF)
package graphqladvanced

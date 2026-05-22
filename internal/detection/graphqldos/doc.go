// Package graphqldos probes a GraphQL endpoint for resource-exhaustion
// attack surface: alias amplification, query-depth bombs, and batched-
// query acceptance. These are the three vectors most commonly missed
// when a team layers per-resolver complexity limits without global
// guardrails.
//
// The detector self-gates on a GraphQL response shape (a data/errors
// envelope) so non-GraphQL endpoints cost one round-trip and no
// findings. Each probe is independent: alias amplification packs N
// aliases into one query, the depth bomb sends N nesting levels of
// __schema.types, and the batched-query probe sends a JSON array of N
// queries. Any probe that returns a successful data envelope is a
// finding — there is no false-positive for "server happens to be
// slow"; the signal is "server accepted a heavy query at all."
package graphqldos

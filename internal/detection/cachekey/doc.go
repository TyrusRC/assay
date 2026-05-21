// Package cachekey probes for cache-key normalization quirks that the
// existing cachepoisoning/ (unkeyed-header reflection) and
// cachedeception/ (extension stripping) packages do not cover.
//
// The class of bug is parser divergence between the upstream cache and
// the downstream application: the cache decides what URL to key on,
// the app decides what URL to process, and a mismatch lets an attacker
// poison the cache for legitimate requests.
//
// Techniques:
//
//   - semicolon_param_cloaking — Tomcat/PHP/some Python frameworks
//     parse `?id=A;id=B` as two `id` parameters, with the last one
//     winning. CDNs and reverse proxies almost universally treat the
//     entire `;...` as part of the first value (or strip it before
//     keying). Result: the cache keys on `?id=A` while the app
//     processes `?id=B`.
//
//   - duplicate_param_pollution — `?id=A&id=B` — caches usually key on
//     the first occurrence; PHP/ASP take the last, Go takes the first
//     by default but apps that iterate the slice may pick either.
//
//   - encoded_slash_normalization — `/a/b` versus `/a%2Fb`. Caches that
//     URL-normalize before keying serve the same cache entry for both,
//     but backends that treat %2F as a literal slash route them to
//     different handlers — a cache-key smuggling primitive.
//
// Detection works by paired-request differential observation: send the
// canonical form, send the quirky form, compare response bodies. A
// stable diff under a fixed input proves the parser divergence. The
// detector does not attempt to confirm the *poisoning* leg (which
// would require modeling the upstream cache) — it flags the
// precondition, leaving exploitability to the analyst.
//
// OWASP mappings:
//   - WSTG-INPV-15 (HTTP request smuggling / parser divergence family)
//   - A05:2025 (Security Misconfiguration)
//   - CWE-444 (Inconsistent Interpretation of HTTP Requests)
package cachekey

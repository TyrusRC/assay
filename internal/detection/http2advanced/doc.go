// Package http2advanced probes HTTP/2 servers for frame-level abuses
// beyond the rapid-reset DoS already covered by internal/detection/h2reset.
//
// Three independent probes are exposed:
//
//   - DetectSettingsFlood: rapidly emits many SETTINGS frames (and a single
//     SETTINGS frame stuffed with a long parameter list) to detect servers
//     that lack any cap on inbound SETTINGS frequency. A hardened server
//     either applies rate-limiting via GOAWAY/ENHANCE_YOUR_CALM, closes the
//     connection, or simply slows the channel; an unmitigated server silently
//     accepts hundreds of SETTINGS in a sub-second window.
//
//   - DetectHPACKPollution: opens two streams in sequence and inserts a
//     unique probe header on stream 1 that gets added to the connection's
//     HPACK dynamic table. Stream 3 makes a normal request; if the server
//     echoes stream-1-only headers back, the HPACK decoder is leaking state
//     across streams (server-side decoder confusion / CVE-like behaviour).
//
//   - DetectFlowControlExhaustion: opens many streams without consuming
//     DATA payloads while advertising tiny WINDOW_UPDATE increments, to
//     check whether the server stalls its entire connection (the canonical
//     flow-control DoS pattern). This probe is destructive — it intentionally
//     starves the connection's flow-control window — and is gated behind
//     DetectOptions.AllowDestructive.
//
// All three probes use raw http2.Framer over a TLS-ALPN ("h2") connection,
// because the abuse surface is framer-level: the stdlib client hides
// SETTINGS, HPACK state and flow-control mechanics from callers.
//
// Findings are mapped to OWASP A05:2025 (Security Misconfiguration) and
// CWE-400 / CWE-770 (resource exhaustion / unbounded resource allocation).
package http2advanced

// Package http2race probes state-change endpoints for race conditions
// using the Single-Packet Attack technique popularized by James Kettle
// in 2023: send N requests concurrently so they land in the server's
// pre-state-change window simultaneously, then verify that the state
// became exhausted (post-burst probe fails).
//
// The detector flags only when (a) the burst returned ≥ 2 successful
// responses AND (b) the post-burst confirmation probe failed. The
// second condition suppresses the obvious idempotent-endpoint false
// positive: an endpoint that always returns 200 isn't a race finding,
// it's just stateless.
//
// The detector uses the standard HTTP client and its connection pool
// (HTTP/2 when negotiated by ALPN, HTTP/1.1 otherwise). The literal
// single-TCP-packet variant requires raw H/2 framer access and is
// future work; the existing client's pool gets close enough for the
// 40-millisecond race windows that most check-then-act bugs leave open.
//
// Off by default — the burst sends real state-change requests.
package http2race

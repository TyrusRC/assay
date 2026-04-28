package racecond

import (
	"context"
	"time"
)

// SyncMode selects the transmission-synchronization primitive.
//
// SyncH1LastByte: open N HTTP/1.1 keep-alive TCP connections, prime each by
// sending the request body up to but not including its final byte, wait for
// the kernel to drain those bytes through any front-end buffer, then release
// the final byte on every connection from a single barrier. This narrows the
// arrival-time window from milliseconds-of-jitter to roughly the time it
// takes the OS to fan out N tiny writes — usually well under a millisecond.
//
// SyncParallel: the legacy goroutine-driven dispatch. No transmission
// synchronization at all; kept as a fallback for targets that do not accept
// keep-alive (e.g., a misbehaving proxy) and as a comparison baseline.
type SyncMode string

const (
	// SyncH1LastByte is the default: HTTP/1.1 last-byte synchronization.
	SyncH1LastByte SyncMode = "h1-last-byte"
	// SyncH2SinglePacket multiplexes N requests on a single HTTP/2
	// connection and releases all END_STREAM-bearing frames in one TCP
	// write. Tighter arrival window than H1 (sub-100µs typical vs
	// sub-millisecond) at the cost of requiring h2 ALPN.
	SyncH2SinglePacket SyncMode = "h2-single-packet"
	// SyncParallel is the simple goroutine fan-out fallback.
	SyncParallel SyncMode = "parallel"
)

// DetectOptions configures a single race-condition probe.
type DetectOptions struct {
	// ConcurrentRequests is how many requests join the burst. Below 2 the
	// probe is meaningless; above 50 most targets start dropping connections.
	ConcurrentRequests int
	// Timeout bounds the entire probe (baseline + burst + read).
	Timeout time.Duration
	// BodyLengthVariance is retained for backward compatibility with the
	// legacy analyzer and ignored by the differential analyzer.
	BodyLengthVariance float64
	// SyncMode picks the transmission primitive (default SyncH1LastByte).
	SyncMode SyncMode
	// PreSyncDelay is how long we wait between writing the request prefixes
	// and releasing the final byte. Long enough that the kernel and any
	// front-end proxy have flushed the prefix, short enough not to trip an
	// idle-timeout. 50ms is a good default for LAN; raise for high-latency.
	PreSyncDelay time.Duration
	// BaselineRequests is the count of sequential warm-up requests issued
	// before the burst. We compare the burst against this distribution to
	// suppress targets where the response naturally varies per-request.
	BaselineRequests int
}

// DefaultOptions returns sensible defaults for a single-target probe.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		ConcurrentRequests: 10,
		Timeout:            15 * time.Second,
		BodyLengthVariance: 0.1,
		SyncMode:           SyncH1LastByte,
		PreSyncDelay:       50 * time.Millisecond,
		BaselineRequests:   3,
	}
}

// recordedResponse captures the bits of a response we use for analysis.
// We deliberately do not retain whole bodies for the burst — N=10 burst
// against a 1MB endpoint would cost 10MB of RAM per probe.
type recordedResponse struct {
	StatusCode    int
	ContentLength int
	BodyHash      string
	Body          string
	Err           error
}

// Verifier is an optional caller-supplied callback that confirms a race
// window was actually exploited rather than just observed. The callback
// inspects post-burst state (e.g. re-fetches a wallet balance, re-reads a
// coupon-redemption count) and returns true only if the state shows that
// more than one of the burst requests had its side effect applied. When
// present and reporting true, findings are promoted to Critical+Confirmed.
type Verifier func(ctx context.Context) (multiEffect bool, evidence string, err error)

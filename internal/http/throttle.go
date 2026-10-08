package http

import (
	"context"
	"sync"
	"time"
)

// throttle paces outbound requests to at most one per interval. It is shared by
// pointer across a client and all its clones, so one rate budget covers every
// request a scan makes — a DAST must not flood the target. A nil throttle, or a
// non-positive interval, imposes no limit.
type throttle struct {
	mu       sync.Mutex
	interval time.Duration
	last     time.Time
}

// newThrottle returns a throttle of perSecond requests, or nil when perSecond is
// not positive (unlimited).
func newThrottle(perSecond float64) *throttle {
	if perSecond <= 0 {
		return nil
	}
	return &throttle{interval: time.Duration(float64(time.Second) / perSecond)}
}

// wait blocks until the next request slot is due, honoring ctx cancellation. It
// reserves the slot under the lock so concurrent callers are paced evenly rather
// than all waking at once.
func (t *throttle) wait(ctx context.Context) error {
	if t == nil || t.interval <= 0 {
		return nil
	}
	t.mu.Lock()
	now := time.Now()
	wait := t.interval - now.Sub(t.last)
	if wait < 0 {
		wait = 0
	}
	t.last = now.Add(wait)
	t.mu.Unlock()

	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

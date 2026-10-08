package http

import (
	"context"
	"testing"
	"time"
)

func TestThrottle_NilAndZeroAreUnlimited(t *testing.T) {
	var tn *throttle
	if err := tn.wait(context.Background()); err != nil {
		t.Errorf("nil throttle must not wait or error: %v", err)
	}
	if newThrottle(0) != nil || newThrottle(-5) != nil {
		t.Error("non-positive rate must yield a nil (unlimited) throttle")
	}
}

func TestThrottle_PacesRequests(t *testing.T) {
	// 50 req/s -> 20ms spacing. Three waits must take at least ~2 intervals.
	th := newThrottle(50)
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := th.wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(start); elapsed < 30*time.Millisecond {
		t.Errorf("3 paced waits took %v, expected >= ~40ms", elapsed)
	}
}

func TestThrottle_RespectsContextCancel(t *testing.T) {
	th := newThrottle(1) // 1s spacing
	_ = th.wait(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := th.wait(ctx); err == nil {
		t.Error("wait must return the context error when cancelled before the slot is due")
	}
}

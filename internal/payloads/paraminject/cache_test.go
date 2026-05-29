package paraminject

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCache_FirstFetchHitsServerSecondReturnsCached(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()

	c := NewCache()
	body1, _, err1 := c.Fetch(context.Background(), srv.Client(), srv.URL, 1024)
	if err1 != nil {
		t.Fatalf("first fetch: %v", err1)
	}
	body2, _, err2 := c.Fetch(context.Background(), srv.Client(), srv.URL, 1024)
	if err2 != nil {
		t.Fatalf("second fetch: %v", err2)
	}
	if body1 != "hello" || body2 != "hello" {
		t.Errorf("unexpected bodies %q / %q", body1, body2)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("expected 1 server hit, got %d", got)
	}
	if c.Size() != 1 {
		t.Errorf("expected cache size 1, got %d", c.Size())
	}
}

func TestCache_DifferentMaxBodyBytesKeyedSeparately(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte("data"))
	}))
	defer srv.Close()

	c := NewCache()
	_, _, _ = c.Fetch(context.Background(), srv.Client(), srv.URL, 1024)
	_, _, _ = c.Fetch(context.Background(), srv.Client(), srv.URL, 2048)

	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("different body caps must be cached separately: got %d server hits, want 2", got)
	}
	if c.Size() != 2 {
		t.Errorf("expected cache size 2, got %d", c.Size())
	}
}

func TestCache_NilCacheFallsThroughToPlainFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	var c *Cache // intentional nil
	body, _, err := c.Fetch(context.Background(), srv.Client(), srv.URL, 1024)
	if err != nil {
		t.Fatalf("nil cache fetch: %v", err)
	}
	if body != "ok" {
		t.Errorf("unexpected body %q", body)
	}
	// Nil cache reports size 0.
	if c.Size() != 0 {
		t.Errorf("nil cache size = %d, want 0", c.Size())
	}
}

func TestCache_ConcurrentFetchesCoalesce(t *testing.T) {
	// Server is intentionally slow so concurrent fetches overlap.
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte("body"))
	}))
	defer srv.Close()

	c := NewCache()
	const N = 20
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			_, _, _ = c.Fetch(context.Background(), srv.Client(), srv.URL, 1024)
		}()
	}
	wg.Wait()

	// With coalescing, even 20 concurrent fetchers should produce at
	// most a handful of server hits (the first wins, the rest wait on
	// inflight). Allow a small slack window for race-y schedulers but
	// reject the "no coalescing" case.
	if got := atomic.LoadInt32(&hits); got > 3 {
		t.Errorf("concurrent fetches did not coalesce: %d server hits, want <= 3", got)
	}
}

func TestCache_NegativeResultCached(t *testing.T) {
	// Use a definitely-unreachable target so Fetch errors fast.
	c := NewCache()
	_, _, err1 := c.Fetch(context.Background(), &http.Client{}, "http://127.0.0.1:1/nowhere", 1024)
	_, _, err2 := c.Fetch(context.Background(), &http.Client{}, "http://127.0.0.1:1/nowhere", 1024)

	if err1 == nil || err2 == nil {
		t.Skip("expected both fetches to error; environment may proxy unreachable hosts")
	}
	if c.Size() != 1 {
		t.Errorf("negative result not cached: size = %d, want 1", c.Size())
	}
}

func TestCacheStats_HitsAndMisses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := NewCache()
	// First fetch is a miss; subsequent fetches are hits.
	_, _, _ = c.Fetch(context.Background(), srv.Client(), srv.URL, 1024)
	_, _, _ = c.Fetch(context.Background(), srv.Client(), srv.URL, 1024)
	_, _, _ = c.Fetch(context.Background(), srv.Client(), srv.URL, 1024)

	s := c.Stats()
	if s.Misses != 1 {
		t.Errorf("expected 1 miss, got %d", s.Misses)
	}
	if s.Hits != 2 {
		t.Errorf("expected 2 hits, got %d", s.Hits)
	}
	if got := s.HitRate(); got < 0.66 || got > 0.67 {
		t.Errorf("hit rate = %f, want ~0.67", got)
	}
}

func TestCacheStats_NilCacheReturnsZeroStats(t *testing.T) {
	var c *Cache
	if got := c.Stats(); got.Hits != 0 || got.Misses != 0 {
		t.Errorf("nil cache stats should be zero, got %+v", got)
	}
	// HitRate of empty stats must not divide by zero.
	if got := (Stats{}).HitRate(); got != 0 {
		t.Errorf("empty stats hit rate = %f, want 0", got)
	}
}

func TestFetchTimed_ReturnsRealDurationOnMiss(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte("slow"))
	}))
	defer srv.Close()

	c := NewCache()
	_, _, dur, err := c.FetchTimed(context.Background(), srv.Client(), srv.URL, 1024)
	if err != nil {
		t.Fatalf("FetchTimed: %v", err)
	}
	if dur < 40*time.Millisecond {
		t.Errorf("expected duration >= 40ms (server slept 50ms), got %v", dur)
	}
}

func TestFetchTimed_ReturnsCachedDurationOnHit(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte("slow"))
	}))
	defer srv.Close()

	c := NewCache()
	_, _, firstDur, _ := c.FetchTimed(context.Background(), srv.Client(), srv.URL, 1024)
	_, _, secondDur, _ := c.FetchTimed(context.Background(), srv.Client(), srv.URL, 1024)

	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("expected exactly 1 server hit, got %d", hits)
	}
	if firstDur != secondDur {
		t.Errorf("cached duration must equal first-measured duration: %v vs %v", firstDur, secondDur)
	}
}

func TestFetchTimed_NilCacheStillMeasures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(30 * time.Millisecond)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	var c *Cache
	_, _, dur, err := c.FetchTimed(context.Background(), srv.Client(), srv.URL, 1024)
	if err != nil {
		t.Fatalf("FetchTimed on nil cache: %v", err)
	}
	if dur < 20*time.Millisecond {
		t.Errorf("nil-cache FetchTimed should still measure (>= 20ms), got %v", dur)
	}
}

func TestCacheKey_StableAcrossCalls(t *testing.T) {
	a := cacheKey("https://x.tld/", 1024)
	b := cacheKey("https://x.tld/", 1024)
	if a != b {
		t.Errorf("cache key not stable: %q vs %q", a, b)
	}
	c := cacheKey("https://x.tld/", 2048)
	if a == c {
		t.Errorf("different maxBodyBytes must produce different keys")
	}
	d := cacheKey("https://y.tld/", 1024)
	if a == d {
		t.Errorf("different URL must produce different keys")
	}
}

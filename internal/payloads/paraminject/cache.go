package paraminject

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Cache shares baseline GET responses across the per-parameter-injection
// detectors that all start with `fetch baseline of target URL`.
//
// Each scan creates one Cache instance and passes it through DetectOptions
// to every detector. The cache keyed by (URL, maxBodyBytes) is a near-100%
// hit rate for the baselines because every detector targeting the same
// URL fetches it with the same body cap. Per-payload fetches (injected
// query string varies per call) are deliberately NOT cached — cache key
// is the exact target URL, and injected URLs differ each time.
//
// The cache is safe for concurrent use by multiple goroutines.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	// inflight serialises concurrent first-time fetches for the same key
	// so we don't fan out N identical baselines just because N detectors
	// raced. Once one fetch lands, the others read the cached result.
	inflight map[string]*inflightEntry
	// hits / misses are atomic counters surfaced via Stats() at scan end
	// so the report can show how much I/O the cache spared.
	hits   atomic.Int64
	misses atomic.Int64
}

type cacheEntry struct {
	body     string
	response *http.Response
	err      error
	duration time.Duration // wall-clock measured on first fetch (0 for cached negative results)
}

type inflightEntry struct {
	done chan struct{}
	ce   cacheEntry
}

// NewCache returns a fresh, empty cache ready for use.
func NewCache() *Cache {
	return &Cache{
		entries:  make(map[string]cacheEntry),
		inflight: make(map[string]*inflightEntry),
	}
}

// Fetch returns the cached baseline body / response for target, or
// fetches it and stores it. Returns whatever paraminject.Fetch would
// have returned — including the error — and caches the negative result
// too so a transient host failure doesn't cause every subsequent
// detector to retry the same dead host.
//
// If c is nil the call falls through to package-level Fetch.
func (c *Cache) Fetch(ctx context.Context, client *http.Client, target string, maxBodyBytes int64) (string, *http.Response, error) {
	body, resp, _, err := c.fetchEntry(ctx, client, target, maxBodyBytes)
	return body, resp, err
}

// FetchTimed is Fetch's variant for time-blind detectors. It returns the
// baseline duration alongside the body / response. On a cache miss the
// duration is freshly measured; on a hit it is the measured duration
// from the very first fetch. Time-blind comparisons stay meaningful
// inside a single scan window because network conditions are typically
// stable across that window.
func (c *Cache) FetchTimed(ctx context.Context, client *http.Client, target string, maxBodyBytes int64) (string, *http.Response, time.Duration, error) {
	return c.fetchEntry(ctx, client, target, maxBodyBytes)
}

// fetchEntry is the internal worker shared by Fetch and FetchTimed.
func (c *Cache) fetchEntry(ctx context.Context, client *http.Client, target string, maxBodyBytes int64) (string, *http.Response, time.Duration, error) {
	if c == nil {
		// nil cache: measure on every call.
		start := time.Now()
		body, resp, err := Fetch(ctx, client, target, maxBodyBytes)
		return body, resp, time.Since(start), err
	}
	key := cacheKey(target, maxBodyBytes)

	// Fast path: cache hit.
	c.mu.RLock()
	if entry, ok := c.entries[key]; ok {
		c.mu.RUnlock()
		c.hits.Add(1)
		return entry.body, entry.response, entry.duration, entry.err
	}
	if pending, ok := c.inflight[key]; ok {
		c.mu.RUnlock()
		c.hits.Add(1)
		<-pending.done
		return pending.ce.body, pending.ce.response, pending.ce.duration, pending.ce.err
	}
	c.mu.RUnlock()

	// Promote to a write lock and re-check.
	c.mu.Lock()
	if entry, ok := c.entries[key]; ok {
		c.mu.Unlock()
		c.hits.Add(1)
		return entry.body, entry.response, entry.duration, entry.err
	}
	if pending, ok := c.inflight[key]; ok {
		c.mu.Unlock()
		c.hits.Add(1)
		<-pending.done
		return pending.ce.body, pending.ce.response, pending.ce.duration, pending.ce.err
	}
	pending := &inflightEntry{done: make(chan struct{})}
	c.inflight[key] = pending
	c.mu.Unlock()

	// Actually fetch outside the lock so concurrent fetches for
	// different targets don't serialise.
	start := time.Now()
	body, resp, err := Fetch(ctx, client, target, maxBodyBytes)
	dur := time.Since(start)
	pending.ce = cacheEntry{body: body, response: resp, err: err, duration: dur}

	c.mu.Lock()
	c.entries[key] = pending.ce
	delete(c.inflight, key)
	c.mu.Unlock()
	close(pending.done)
	c.misses.Add(1)

	return body, resp, dur, err
}

// Stats reports the cache hit / miss counters since the cache was
// created. Useful for surfacing in scan summaries to show how much
// duplicate I/O the cache spared.
type Stats struct {
	Hits   int64
	Misses int64
}

// HitRate returns hits / (hits + misses), or 0 if the cache was never
// consulted. Safe on a zero-value Stats.
func (s Stats) HitRate() float64 {
	total := s.Hits + s.Misses
	if total == 0 {
		return 0
	}
	return float64(s.Hits) / float64(total)
}

// Stats snapshots the current counter values. nil cache returns zero
// stats so callers can call unconditionally.
func (c *Cache) Stats() Stats {
	if c == nil {
		return Stats{}
	}
	return Stats{Hits: c.hits.Load(), Misses: c.misses.Load()}
}

// Size returns the number of cached entries. Useful for tests and for
// surfacing the cache hit rate at scan end.
func (c *Cache) Size() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

func cacheKey(target string, maxBodyBytes int64) string {
	return fmt.Sprintf("%d|%s", maxBodyBytes, target)
}

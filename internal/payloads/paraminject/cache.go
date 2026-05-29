package paraminject

import (
	"context"
	"fmt"
	"net/http"
	"sync"
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
}

type cacheEntry struct {
	body     string
	response *http.Response
	err      error
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
	if c == nil {
		return Fetch(ctx, client, target, maxBodyBytes)
	}
	key := cacheKey(target, maxBodyBytes)

	// Fast path: cache hit.
	c.mu.RLock()
	if entry, ok := c.entries[key]; ok {
		c.mu.RUnlock()
		return entry.body, entry.response, entry.err
	}
	if pending, ok := c.inflight[key]; ok {
		c.mu.RUnlock()
		// Another goroutine is fetching the same key — wait for it.
		<-pending.done
		return pending.ce.body, pending.ce.response, pending.ce.err
	}
	c.mu.RUnlock()

	// Promote to a write lock and re-check.
	c.mu.Lock()
	if entry, ok := c.entries[key]; ok {
		c.mu.Unlock()
		return entry.body, entry.response, entry.err
	}
	if pending, ok := c.inflight[key]; ok {
		c.mu.Unlock()
		<-pending.done
		return pending.ce.body, pending.ce.response, pending.ce.err
	}
	pending := &inflightEntry{done: make(chan struct{})}
	c.inflight[key] = pending
	c.mu.Unlock()

	// Actually fetch outside the lock so concurrent fetches for
	// different targets don't serialise.
	body, resp, err := Fetch(ctx, client, target, maxBodyBytes)
	pending.ce = cacheEntry{body: body, response: resp, err: err}

	c.mu.Lock()
	c.entries[key] = pending.ce
	delete(c.inflight, key)
	c.mu.Unlock()
	close(pending.done)

	return body, resp, err
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

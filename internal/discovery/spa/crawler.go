package spa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/headless"
)

// CrawlOptions tunes crawler behavior. Zero values are safe defaults
// (depth/pages unlimited within reason, no origin filtering, 1s settle).
type CrawlOptions struct {
	// MaxDepth bounds BFS depth from the start URL. Zero means
	// start-page-only.
	MaxDepth int
	// MaxPages caps total navigated pages. Zero means a built-in safety
	// limit (DefaultMaxPages).
	MaxPages int
	// SameOriginOnly drops URLs whose scheme+host differ from the
	// start URL.
	SameOriginOnly bool
	// WaitFor is the extra dwell time after page load to let JS
	// hydrate routes (i.e., the post-load network-idle window). Zero
	// uses DefaultWaitFor.
	WaitFor time.Duration
}

// DefaultMaxPages bounds runaway BFS when CrawlOptions.MaxPages is zero.
const DefaultMaxPages = 25

// DefaultWaitFor is the dwell time after load when CrawlOptions.WaitFor
// is zero. Chosen empirically: long enough for client routers to
// pushState, short enough to keep the suite snappy.
const DefaultWaitFor = 500 * time.Millisecond

// Crawler drives a headless browser to discover routes in an SPA.
type Crawler struct {
	pool *headless.Pool
}

// NewCrawler wires up a Crawler against the given pool. Pool must be a
// running pool; a nil pool causes Crawl to error.
func NewCrawler(pool *headless.Pool) *Crawler {
	return &Crawler{pool: pool}
}

// Crawl loads startURL, waits for JS to settle, and returns every URL
// the page either anchored or registered via the History API. Results
// are deduplicated and sorted for stable output.
//
// Crawl is intentionally single-level for the common SPA case (the
// "shell" page that lists routes). When MaxDepth > 0, discovered URLs
// are loaded in turn and re-mined, BFS-style, until MaxDepth or
// MaxPages is exhausted.
func (c *Crawler) Crawl(ctx context.Context, startURL string, opts CrawlOptions) ([]string, error) {
	if c == nil || c.pool == nil {
		return nil, errors.New("spa: crawler has no headless pool")
	}
	if startURL == "" {
		return nil, errors.New("spa: empty start URL")
	}
	startU, err := url.Parse(startURL)
	if err != nil {
		return nil, fmt.Errorf("spa: parse start URL: %w", err)
	}

	wait := opts.WaitFor
	if wait <= 0 {
		wait = DefaultWaitFor
	}
	maxPages := opts.MaxPages
	if maxPages <= 0 {
		maxPages = DefaultMaxPages
	}

	type queueItem struct {
		url   string
		depth int
	}

	visited := make(map[string]struct{})
	results := make(map[string]struct{})
	queue := []queueItem{{url: startURL, depth: 0}}
	pages := 0

	for len(queue) > 0 && pages < maxPages {
		// Honor caller cancellation between pages.
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		cur := queue[0]
		queue = queue[1:]
		if _, ok := visited[cur.url]; ok {
			continue
		}
		visited[cur.url] = struct{}{}
		pages++

		discovered, err := c.minePage(ctx, cur.url, wait)
		if err != nil {
			// Don't abort the whole crawl on a single page error — the
			// SPA might gate routes behind login, throw on missing
			// resources, etc. Move on.
			continue
		}

		for _, raw := range discovered {
			abs := normalizeURL(startU, raw)
			if abs == "" {
				continue
			}
			if opts.SameOriginOnly && !sameOrigin(startU, abs) {
				continue
			}
			if _, ok := results[abs]; ok {
				continue
			}
			results[abs] = struct{}{}

			// Recurse into in-scope URLs if depth budget allows.
			if cur.depth < opts.MaxDepth && sameOrigin(startU, abs) {
				queue = append(queue, queueItem{url: abs, depth: cur.depth + 1})
			}
		}
	}

	out := make([]string, 0, len(results))
	for u := range results {
		out = append(out, u)
	}
	sort.Strings(out)
	return out, nil
}

// minePage navigates to pageURL, waits for JS to hydrate routes, and
// returns the raw URL strings the page surfaced via anchors and via
// the History API.
func (c *Crawler) minePage(ctx context.Context, pageURL string, wait time.Duration) ([]string, error) {
	page, err := c.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer c.pool.Release(page)

	if err := page.Navigate(ctx, pageURL); err != nil {
		return nil, err
	}

	// Allow JS to hydrate routes. We use a plain sleep gated on ctx
	// because the headless package exposes no network-idle primitive;
	// the dwell time is short and bounded by CrawlOptions.WaitFor.
	select {
	case <-time.After(wait):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Harvest in a single JS round-trip: anchor hrefs plus the current
	// document.location (covers history.pushState the page may have
	// done during/after hydration). We deliberately capture
	// location.href as well as anchors so SPA shells that pushState
	// into a new route are detected.
	expr := `(function() {
		var out = [];
		var anchors = document.querySelectorAll('a[href]');
		for (var i = 0; i < anchors.length; i++) {
			var h = anchors[i].getAttribute('href');
			if (h) out.push(h);
		}
		try { out.push(String(window.location.href)); } catch(e) {}
		return JSON.stringify(out);
	})()`
	raw, err := page.EvalJS(ctx, expr)
	if err != nil {
		return nil, err
	}
	var hrefs []string
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &hrefs); err != nil {
			return nil, fmt.Errorf("spa: parse hrefs: %w", err)
		}
	}
	return hrefs, nil
}

// normalizeURL resolves raw against base, drops empty/anchor/JS URLs,
// and returns the canonical absolute form.
func normalizeURL(base *url.URL, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	lower := strings.ToLower(raw)
	// In-page anchors and non-HTTP schemes are not useful as
	// discovered endpoints.
	if strings.HasPrefix(raw, "#") ||
		strings.HasPrefix(lower, "javascript:") ||
		strings.HasPrefix(lower, "mailto:") ||
		strings.HasPrefix(lower, "tel:") ||
		strings.HasPrefix(lower, "data:") {
		return ""
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(ref)
	// Strip the fragment — different fragments on the same path are
	// the same endpoint as far as discovery is concerned.
	resolved.Fragment = ""
	return resolved.String()
}

// sameOrigin reports whether u shares scheme+host with base.
func sameOrigin(base *url.URL, u string) bool {
	parsed, err := url.Parse(u)
	if err != nil {
		return false
	}
	return parsed.Scheme == base.Scheme && parsed.Host == base.Host
}

package crawl

import (
	"context"
	"net/url"
)

// Default bounds for a crawl when the caller leaves them zero.
const (
	defaultMaxRequests = 200
	defaultMaxStates   = 100
)

// Fetcher retrieves the HTML body at a URL. It is the crawler's only I/O
// dependency, so crawls are fully testable with an in-memory fetcher.
type Fetcher interface {
	Fetch(ctx context.Context, url string) (string, error)
}

// Crawler performs a state-aware crawl.
type Crawler struct {
	// Fetcher retrieves page bodies.
	Fetcher Fetcher
	// MaxRequests caps total fetches (default 200).
	MaxRequests int
	// MaxStates caps distinct states expanded (default 100).
	MaxStates int
	// SameHostOnly restricts the crawl to the seeds' hosts.
	SameHostOnly bool
}

// Result reports what a crawl discovered.
type Result struct {
	// Endpoints are the distinct URLs discovered (fetched pages plus form
	// actions), in discovery order.
	Endpoints []string
	// States is the number of distinct page states expanded.
	States int
	// Requests is the number of fetches performed.
	Requests int
}

// Crawl explores from the seeds, expanding each distinct page *state* once
// (deduplicated by structural fingerprint) and collecting every reachable
// endpoint. Expanding by state rather than URL avoids re-walking equivalent
// pages and still records every URL that maps to a known state.
func (c *Crawler) Crawl(ctx context.Context, seeds []string) Result {
	maxReq := c.MaxRequests
	if maxReq <= 0 {
		maxReq = defaultMaxRequests
	}
	maxStates := c.MaxStates
	if maxStates <= 0 {
		maxStates = defaultMaxStates
	}

	hosts := seedHosts(seeds)
	var res Result
	queuedOrSeen := map[string]bool{}
	endpointSet := map[string]bool{}
	states := map[string]bool{}

	queue := make([]string, 0, len(seeds))
	for _, s := range seeds {
		if !queuedOrSeen[s] {
			queuedOrSeen[s] = true
			queue = append(queue, s)
		}
	}

	addEndpoint := func(u string) {
		if u == "" || endpointSet[u] {
			return
		}
		endpointSet[u] = true
		res.Endpoints = append(res.Endpoints, u)
	}

	for len(queue) > 0 {
		if res.Requests >= maxReq || len(states) >= maxStates {
			break
		}
		cur := queue[0]
		queue = queue[1:]

		if c.SameHostOnly && !hostAllowed(cur, hosts) {
			continue
		}

		body, err := c.Fetcher.Fetch(ctx, cur)
		res.Requests++
		if err != nil {
			continue
		}
		addEndpoint(cur)

		fp := Fingerprint(body)
		if states[fp] {
			// Equivalent state already expanded — keep the endpoint, skip the walk.
			continue
		}
		states[fp] = true

		c.expand(cur, body, hosts, queuedOrSeen, &queue, addEndpoint)
	}

	res.States = len(states)
	return res
}

// expand enqueues a page's same-host links and records its form actions.
func (c *Crawler) expand(cur, body string, hosts, seen map[string]bool, queue *[]string, addEndpoint func(string)) {
	for _, href := range extractLinks(body) {
		abs := resolveURL(cur, href)
		if abs == "" {
			continue
		}
		if c.SameHostOnly && !hostAllowed(abs, hosts) {
			continue
		}
		if !seen[abs] {
			seen[abs] = true
			*queue = append(*queue, abs)
		}
	}
	for _, f := range extractForms(body) {
		if abs := resolveURL(cur, f.Action); abs != "" {
			if !c.SameHostOnly || hostAllowed(abs, hosts) {
				addEndpoint(abs)
			}
		}
	}
}

// resolveURL resolves href against base and strips the fragment.
func resolveURL(base, href string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ""
	}
	r, err := url.Parse(href)
	if err != nil {
		return ""
	}
	resolved := b.ResolveReference(r)
	resolved.Fragment = ""
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return ""
	}
	return resolved.String()
}

// seedHosts returns the set of hosts among the seeds.
func seedHosts(seeds []string) map[string]bool {
	hosts := map[string]bool{}
	for _, s := range seeds {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			hosts[u.Host] = true
		}
	}
	return hosts
}

// hostAllowed reports whether rawURL's host is in the allowed set.
func hostAllowed(rawURL string, hosts map[string]bool) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return hosts[u.Host]
}

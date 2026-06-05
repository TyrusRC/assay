package scanner

import (
	"context"
	"fmt"
	"os"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/discovery/spa"
)

// CrawlURLs drives the headless browser to discover same-origin routes
// reachable from seedURL. It returns nil (no error) when SPA crawling is
// disabled or no headless pool is available, so callers can invoke it
// unconditionally and degrade gracefully without Chrome.
func (s *InternalScanner) CrawlURLs(ctx context.Context, seedURL string) ([]string, error) {
	if s.config == nil || !s.config.EnableSPACrawl || s.headlessPool == nil {
		return nil, nil
	}
	crawler := spa.NewCrawler(s.headlessPool)
	return crawler.Crawl(ctx, seedURL, spa.CrawlOptions{
		MaxDepth:       s.config.CrawlMaxDepth,
		MaxPages:       s.config.CrawlMaxPages,
		SameOriginOnly: true,
	})
}

// expandWithCrawl crawls each seed (when SPA crawling is enabled) and returns
// the seed targets plus any newly discovered same-origin URLs. When crawling
// is disabled or unavailable it returns the seeds unchanged. Crawl errors are
// reported on errorsChan and do not abort the scan.
func expandWithCrawl(ctx context.Context, s *InternalScanner, seeds []*core.Target, verbose bool, errorsChan chan<- string) []*core.Target {
	if s == nil || s.config == nil || !s.config.EnableSPACrawl || s.headlessPool == nil {
		return seeds
	}
	var discovered []string
	for _, seed := range seeds {
		urls, err := s.CrawlURLs(ctx, seed.URL())
		if err != nil {
			errorsChan <- fmt.Sprintf("spa-crawler: %v", err)
			continue
		}
		discovered = append(discovered, urls...)
	}
	merged := mergeDiscoveredTargets(seeds, discovered)
	if verbose && len(merged) > len(seeds) {
		fmt.Fprintf(os.Stderr, "[*] SPA crawl discovered %d additional URL(s)\n", len(merged)-len(seeds))
	}
	return merged
}

// mergeDiscoveredTargets returns the seed targets plus any discovered URLs
// not already present, deduplicated by URL string. Discovered URLs that fail
// to parse as targets are skipped. Seed order is preserved; new URLs are
// appended in discovery order.
func mergeDiscoveredTargets(seeds []*core.Target, discovered []string) []*core.Target {
	seen := make(map[string]bool, len(seeds))
	out := make([]*core.Target, 0, len(seeds)+len(discovered))
	for _, t := range seeds {
		if t == nil || seen[t.URL()] {
			continue
		}
		seen[t.URL()] = true
		out = append(out, t)
	}
	for _, raw := range discovered {
		if seen[raw] {
			continue
		}
		t, err := core.NewTarget(raw)
		if err != nil {
			continue
		}
		if seen[t.URL()] {
			continue
		}
		seen[raw] = true
		seen[t.URL()] = true
		out = append(out, t)
	}
	return out
}

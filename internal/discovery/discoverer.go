package discovery

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
	"golang.org/x/net/html"
)

// hostRootURL returns scheme://host + path for targetURL, so a discoverer can
// fetch a well-known resource (robots.txt, an OpenAPI spec) at the host root.
// The second return is false when targetURL does not parse or has no host.
func hostRootURL(targetURL, path string) (string, bool) {
	u, err := url.Parse(targetURL)
	if err != nil || u.Host == "" {
		return "", false
	}
	return u.Scheme + "://" + u.Host + path, true
}

// Discoverer finds injectable parameters from a specific source.
type Discoverer interface {
	// Name returns the discoverer's identifier.
	Name() string
	// Discover extracts parameters from the target URL and its HTTP response.
	Discover(ctx context.Context, targetURL string, resp *http.Response) ([]core.Parameter, error)
}

// DiscoveryResult aggregates results from all discoverers.
type DiscoveryResult struct {
	Parameters []core.Parameter
	Errors     []string
	Sources    map[string]int // discoverer name -> param count
}

// Pipeline orchestrates all discoverers concurrently.
type Pipeline struct {
	client      *http.Client
	discoverers []Discoverer
	MaxCrawl    int // max pages to crawl (0 = default 50)
}

// NewPipeline creates a new discovery pipeline with the given HTTP client.
func NewPipeline(client *http.Client) *Pipeline {
	return &Pipeline{
		client:      client,
		discoverers: make([]Discoverer, 0),
		MaxCrawl:    30,
	}
}

// Register adds a discoverer to the pipeline.
func (p *Pipeline) Register(d Discoverer) {
	p.discoverers = append(p.discoverers, d)
}

// Discoverers returns the registered discoverers.
func (p *Pipeline) Discoverers() []Discoverer {
	return p.discoverers
}

// Run crawls same-origin links from the target, then runs all discoverers on
// each crawled page. Results are deduplicated by (Name, Location, SourceURL).
func (p *Pipeline) Run(ctx context.Context, targetURL string) (*DiscoveryResult, error) {
	result := &DiscoveryResult{
		Parameters: make([]core.Parameter, 0),
		Sources:    make(map[string]int),
	}

	if len(p.discoverers) == 0 {
		return result, nil
	}

	maxPages := p.MaxCrawl
	if maxPages <= 0 {
		maxPages = 50
	}

	// Parse target to determine origin for same-origin checks
	targetParsed, err := url.Parse(targetURL)
	if err != nil {
		return result, err
	}
	origin := targetParsed.Scheme + "://" + targetParsed.Host

	// BFS crawl: fetch pages, extract links, queue unseen same-origin URLs
	visited := make(map[string]bool)
	type pageResult struct {
		url  string
		resp *http.Response
	}
	var pages []pageResult

	queue := []string{targetURL}
	visited[targetURL] = true

	for len(queue) > 0 && len(pages) < maxPages {
		select {
		case <-ctx.Done():
			break
		default:
		}

		cur := queue[0]
		queue = queue[1:]

		resp, fetchErr := p.client.Get(ctx, cur)
		if fetchErr != nil {
			continue
		}
		pages = append(pages, pageResult{url: cur, resp: resp})

		// Extract same-origin links from HTML
		links := extractLinks(resp.Body, origin, cur)
		for _, link := range links {
			if !visited[link] && len(visited) < maxPages {
				visited[link] = true
				queue = append(queue, link)
			}
		}
	}

	fmt.Fprintf(os.Stderr, "[*] Crawled %d pages from %s\n", len(pages), targetURL)

	// Run all discoverers on each page
	type discoveryOutput struct {
		name   string
		params []core.Parameter
		err    error
	}

	outputCh := make(chan discoveryOutput, len(p.discoverers)*len(pages))
	var wg sync.WaitGroup

	for i, page := range pages {
		for _, d := range p.discoverers {
			// The reflected-param discoverer is expensive (65 HTTP
			// probes) and app-wide — run it only on the root page.
			if i > 0 {
				if _, ok := d.(*ReflectedParamDiscoverer); ok {
					continue
				}
			}
			wg.Add(1)
			go func(disc Discoverer, pageURL string, resp *http.Response) {
				defer wg.Done()
				params, discErr := disc.Discover(ctx, pageURL, resp)
				// Tag each param with its source URL
				for i := range params {
					if params[i].SourceURL == "" {
						params[i].SourceURL = pageURL
					}
				}
				outputCh <- discoveryOutput{
					name:   disc.Name(),
					params: params,
					err:    discErr,
				}
			}(d, page.url, page.resp)
		}
	}

	go func() {
		wg.Wait()
		close(outputCh)
	}()

	// Collect and deduplicate: same param name + location on the same page = 1
	// but same param name + location on different pages = separate (different
	// SQL queries behind the same form field name)
	seen := make(map[string]bool)
	for out := range outputCh {
		if out.err != nil {
			result.Errors = append(result.Errors, out.name+": "+out.err.Error())
			continue
		}
		count := 0
		for _, param := range out.params {
			key := param.Name + ":" + param.Location + ":" + param.SourceURL
			if !seen[key] {
				seen[key] = true
				result.Parameters = append(result.Parameters, param)
				count++
			}
		}
		result.Sources[out.name] += count
	}

	return result, nil
}

// extractLinks parses HTML and returns same-origin absolute URLs from <a href>.
func extractLinks(body, origin, baseURL string) []string {
	if body == "" {
		return nil
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}

	var links []string
	seen := make(map[string]bool)

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, a := range n.Attr {
				if strings.EqualFold(a.Key, "href") {
					resolved := resolveURL(base, a.Val)
					if resolved != "" && strings.HasPrefix(resolved, origin) && !seen[resolved] {
						// Skip anchors, javascript:, mailto:, etc.
						if !strings.Contains(resolved, "#") || strings.Index(resolved, "#") > len(origin) {
							clean := strings.SplitN(resolved, "#", 2)[0]
							if clean != "" && !seen[clean] {
								seen[clean] = true
								links = append(links, clean)
							}
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return links
}

// resolveURL resolves a possibly-relative href against a base URL.
func resolveURL(base *url.URL, href string) string {
	href = strings.TrimSpace(href)
	if href == "" || strings.HasPrefix(href, "javascript:") || strings.HasPrefix(href, "mailto:") {
		return ""
	}
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}
	return base.ResolveReference(ref).String()
}

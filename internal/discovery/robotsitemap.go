package discovery

import (
	"bufio"
	"context"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

// RobotsSitemapDiscoverer extracts path segments from robots.txt directives.
type RobotsSitemapDiscoverer struct{ client *http.Client }

// NewRobotsSitemapDiscoverer creates a new RobotsSitemapDiscoverer.
func NewRobotsSitemapDiscoverer() *RobotsSitemapDiscoverer {
	return &RobotsSitemapDiscoverer{}
}

// WithClient lets the discoverer fetch /robots.txt at the host root itself,
// instead of only parsing the scanned URL's response. The client carries the
// scan's scope and rate limit.
func (r *RobotsSitemapDiscoverer) WithClient(c *http.Client) *RobotsSitemapDiscoverer {
	r.client = c
	return r
}

// Name returns the discoverer identifier.
func (r *RobotsSitemapDiscoverer) Name() string {
	return "robotsitemap"
}

// Discover extracts path segments from Disallow and Allow directives. With a
// client set it fetches /robots.txt at the host root; otherwise it parses the
// response it was handed (used when the scanned URL is robots.txt itself).
func (r *RobotsSitemapDiscoverer) Discover(ctx context.Context, targetURL string, resp *http.Response) ([]core.Parameter, error) {
	body := ""
	if resp != nil {
		body = resp.Body
	}
	if r.client != nil {
		if robotsURL, ok := hostRootURL(targetURL, "/robots.txt"); ok {
			if rr, err := r.client.Get(ctx, robotsURL); err == nil && rr.Body != "" {
				body = rr.Body
			}
		}
	}
	if body == "" {
		return nil, nil
	}

	seen := make(map[string]bool)
	var params []core.Parameter

	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		var path string
		if strings.HasPrefix(line, "Disallow:") {
			path = strings.TrimSpace(strings.TrimPrefix(line, "Disallow:"))
		} else if strings.HasPrefix(line, "Allow:") {
			path = strings.TrimSpace(strings.TrimPrefix(line, "Allow:"))
		} else {
			continue
		}

		if path == "" {
			continue
		}

		segments := strings.Split(strings.Trim(path, "/"), "/")
		for _, seg := range segments {
			seg = strings.TrimSpace(seg)
			if seg == "" || seen[seg] {
				continue
			}
			seen[seg] = true
			params = append(params, core.Parameter{
				Name:     seg,
				Location: core.ParamLocationPath,
			})
		}
	}

	return params, nil
}

package discovery

import (
	"bufio"
	"context"
	"strings"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

// RobotsSitemapDiscoverer extracts path segments from robots.txt directives.
type RobotsSitemapDiscoverer struct{}

// NewRobotsSitemapDiscoverer creates a new RobotsSitemapDiscoverer.
func NewRobotsSitemapDiscoverer() *RobotsSitemapDiscoverer {
	return &RobotsSitemapDiscoverer{}
}

// Name returns the discoverer identifier.
func (r *RobotsSitemapDiscoverer) Name() string {
	return "robotsitemap"
}

// Discover extracts path segments from Disallow and Allow directives.
func (r *RobotsSitemapDiscoverer) Discover(_ context.Context, _ string, resp *http.Response) ([]core.Parameter, error) {
	if resp == nil || resp.Body == "" {
		return nil, nil
	}

	seen := make(map[string]bool)
	var params []core.Parameter

	scanner := bufio.NewScanner(strings.NewReader(resp.Body))
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

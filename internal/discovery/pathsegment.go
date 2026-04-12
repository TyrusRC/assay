package discovery

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

// Patterns for detecting injectable path segments.
var (
	numericRe = regexp.MustCompile(`^[0-9]+$`)
	uuidRe    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	base64Re  = regexp.MustCompile(`^[A-Za-z0-9+/=]{16,}$`)
	hexRe     = regexp.MustCompile(`^[0-9a-fA-F]{8,}$`)
)

// resourcePrefixes are path segments that typically precede a resource identifier.
var resourcePrefixes = map[string]bool{
	"users": true, "user": true,
	"items": true, "item": true,
	"posts": true, "post": true,
	"orders": true, "order": true,
	"products": true, "product": true,
	"accounts": true, "account": true,
	"documents": true, "document": true,
	"messages": true, "message": true,
	"files": true, "file": true,
	"images": true, "image": true,
	"comments": true, "comment": true,
	"articles": true, "article": true,
	"categories": true, "category": true,
	"groups": true, "group": true,
	"projects": true, "project": true,
	"tasks": true, "task": true,
	"tickets": true, "ticket": true,
	"invoices": true, "invoice": true,
	"customers": true, "customer": true,
}

// PathSegmentDiscoverer detects injectable path segments in URLs.
// It extends basic numeric/UUID detection with base64, hex, and
// segments following resource-type paths.
type PathSegmentDiscoverer struct{}

// NewPathSegmentDiscoverer creates a new PathSegmentDiscoverer.
func NewPathSegmentDiscoverer() *PathSegmentDiscoverer {
	return &PathSegmentDiscoverer{}
}

// Name returns the discoverer identifier.
func (p *PathSegmentDiscoverer) Name() string {
	return "pathsegment"
}

// Discover extracts injectable path segment parameters from the target URL.
func (p *PathSegmentDiscoverer) Discover(_ context.Context, targetURL string, _ *http.Response) ([]core.Parameter, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, nil
	}

	segments := strings.Split(parsedURL.Path, "/")
	var params []core.Parameter

	segmentIdx := 0
	prevSegment := ""
	for _, seg := range segments {
		if seg == "" {
			continue
		}

		paramType := ""
		switch {
		case numericRe.MatchString(seg):
			paramType = "number"
		case uuidRe.MatchString(seg):
			paramType = "string"
		case base64Re.MatchString(seg):
			paramType = "string"
		case hexRe.MatchString(seg):
			paramType = "string"
		case resourcePrefixes[strings.ToLower(prevSegment)]:
			// Segment follows a resource-type path like /users/<something>
			paramType = "string"
		}

		if paramType != "" {
			params = append(params, core.Parameter{
				Name:     fmt.Sprintf("path_%d", segmentIdx),
				Location: core.ParamLocationPath,
				Value:    seg,
				Type:     paramType,
			})
		}

		prevSegment = seg
		segmentIdx++
	}

	return params, nil
}

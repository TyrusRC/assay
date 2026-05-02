package discovery

import (
	"context"
	"net/url"
	"regexp"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// HTMLCommentDiscoverer extracts parameter hints from HTML comments.
type HTMLCommentDiscoverer struct{}

// NewHTMLCommentDiscoverer creates a new HTMLCommentDiscoverer.
func NewHTMLCommentDiscoverer() *HTMLCommentDiscoverer {
	return &HTMLCommentDiscoverer{}
}

// Name returns the discoverer identifier.
func (h *HTMLCommentDiscoverer) Name() string {
	return "htmlcomment"
}

var (
	commentRegex   = regexp.MustCompile(`<!--([\s\S]*?)-->`)
	kvRegex        = regexp.MustCompile(`(\w+)=(\S+)`)
	queryRegex     = regexp.MustCompile(`\?([^\s"']+)`)
	paramMentionAfter  = regexp.MustCompile(`(?:parameter|param)\s*[:\s]\s*(\w+)`)
	paramMentionBefore = regexp.MustCompile(`(\w+)\s+(?:parameter|param)\b`)
)

// Discover extracts parameters from HTML comments.
func (h *HTMLCommentDiscoverer) Discover(_ context.Context, _ string, resp *http.Response) ([]core.Parameter, error) {
	if resp == nil || resp.Body == "" {
		return nil, nil
	}

	matches := commentRegex.FindAllStringSubmatch(resp.Body, -1)
	if len(matches) == 0 {
		return nil, nil
	}

	seen := make(map[string]bool)
	var params []core.Parameter

	for _, m := range matches {
		comment := m[1]

		// Extract URL query params first (so we don't also match them as kv)
		queryMatches := queryRegex.FindAllStringSubmatch(comment, -1)
		for _, qm := range queryMatches {
			values, err := url.ParseQuery(qm[1])
			if err != nil {
				continue
			}
			for key, vals := range values {
				if seen[key] {
					continue
				}
				seen[key] = true
				val := ""
				if len(vals) > 0 {
					val = vals[0]
				}
				params = append(params, core.Parameter{
					Name:     key,
					Location: core.ParamLocationQuery,
					Value:    val,
				})
			}
		}

		// Extract key=value patterns
		kvMatches := kvRegex.FindAllStringSubmatch(comment, -1)
		for _, kvm := range kvMatches {
			key := kvm[1]
			value := kvm[2]
			if seen[key] {
				continue
			}
			seen[key] = true
			params = append(params, core.Parameter{
				Name:     key,
				Location: core.ParamLocationQuery,
				Value:    value,
			})
		}

		// Extract "parameter: name" or "name parameter" mentions
		for _, re := range []*regexp.Regexp{paramMentionAfter, paramMentionBefore} {
			paramMatches := re.FindAllStringSubmatch(comment, -1)
			for _, pm := range paramMatches {
				name := pm[1]
				if seen[name] {
					continue
				}
				seen[name] = true
				params = append(params, core.Parameter{
					Name:     name,
					Location: core.ParamLocationQuery,
				})
			}
		}
	}

	if len(params) == 0 {
		return nil, nil
	}

	return params, nil
}

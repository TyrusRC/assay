package discovery

import (
	"context"
	"regexp"
	"strings"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

// xmlElementRe matches XML element opening tags and extracts the element name.
var xmlElementRe = regexp.MustCompile(`<([a-zA-Z][a-zA-Z0-9_-]*)[\s/>]`)

// skipHTMLTags are common structural HTML tags that should not be treated as parameters.
var skipHTMLTags = map[string]bool{
	"html": true, "head": true, "body": true, "div": true,
	"span": true, "p": true, "br": true, "hr": true,
	"meta": true, "link": true, "script": true, "style": true,
}

// XMLBodyDiscoverer extracts injectable parameters from XML response bodies.
// It parses element names using regex and returns them as body parameters.
type XMLBodyDiscoverer struct{}

// NewXMLBodyDiscoverer creates a new XMLBodyDiscoverer.
func NewXMLBodyDiscoverer() *XMLBodyDiscoverer {
	return &XMLBodyDiscoverer{}
}

// Name returns the discoverer identifier.
func (x *XMLBodyDiscoverer) Name() string {
	return "xmlbody"
}

// Discover extracts element names from an XML response body.
// Only processes responses with Content-Type application/xml or text/xml.
func (x *XMLBodyDiscoverer) Discover(_ context.Context, _ string, resp *http.Response) ([]core.Parameter, error) {
	if resp == nil || resp.Body == "" {
		return nil, nil
	}

	if !strings.Contains(resp.ContentType, "application/xml") && !strings.Contains(resp.ContentType, "text/xml") {
		return nil, nil
	}

	matches := xmlElementRe.FindAllStringSubmatch(resp.Body, -1)
	if len(matches) == 0 {
		return nil, nil
	}

	var params []core.Parameter
	seen := make(map[string]bool)

	for _, match := range matches {
		name := match[1]
		nameLower := strings.ToLower(name)

		if skipHTMLTags[nameLower] {
			continue
		}

		if seen[name] {
			continue
		}
		seen[name] = true

		params = append(params, core.Parameter{
			Name:     name,
			Location: core.ParamLocationBody,
			Value:    "",
			Type:     "string",
		})
	}

	return params, nil
}

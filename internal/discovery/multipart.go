package discovery

import (
	"context"
	"strings"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
	"golang.org/x/net/html"
)

// MultipartDiscoverer extracts input names from multipart/form-data forms.
type MultipartDiscoverer struct{}

// NewMultipartDiscoverer creates a new MultipartDiscoverer.
func NewMultipartDiscoverer() *MultipartDiscoverer {
	return &MultipartDiscoverer{}
}

// Name returns the discoverer identifier.
func (m *MultipartDiscoverer) Name() string {
	return "multipart"
}

// Discover extracts parameters from multipart/form-data forms.
func (m *MultipartDiscoverer) Discover(_ context.Context, _ string, resp *http.Response) ([]core.Parameter, error) {
	if resp == nil || resp.Body == "" {
		return nil, nil
	}

	doc, err := html.Parse(strings.NewReader(resp.Body))
	if err != nil {
		return nil, nil
	}

	var params []core.Parameter
	m.walkNode(doc, false, &params)

	if len(params) == 0 {
		return nil, nil
	}

	return params, nil
}

// walkNode traverses HTML to find multipart forms and their inputs.
func (m *MultipartDiscoverer) walkNode(n *html.Node, inMultipart bool, params *[]core.Parameter) {
	if n.Type == html.ElementNode {
		if n.Data == "form" {
			enctype := m.getAttr(n, "enctype")
			isMultipart := strings.EqualFold(enctype, "multipart/form-data")
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				m.walkNode(c, isMultipart, params)
			}
			return
		}

		if inMultipart && n.Data == "input" {
			name := m.getAttr(n, "name")
			if name != "" {
				*params = append(*params, core.Parameter{
					Name:     name,
					Location: core.ParamLocationBody,
				})
			}
		}
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		m.walkNode(c, inMultipart, params)
	}
}

// getAttr returns the value of the named attribute.
func (m *MultipartDiscoverer) getAttr(n *html.Node, name string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, name) {
			return a.Val
		}
	}
	return ""
}

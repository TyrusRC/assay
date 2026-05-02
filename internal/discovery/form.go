package discovery

import (
	"context"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
	"golang.org/x/net/html"
)

// FormDiscoverer extracts injectable parameters from HTML forms.
// It parses <form> elements and extracts <input>, <textarea>, and <select> fields.
type FormDiscoverer struct{}

// NewFormDiscoverer creates a new FormDiscoverer.
func NewFormDiscoverer() *FormDiscoverer {
	return &FormDiscoverer{}
}

// Name returns the discoverer identifier.
func (f *FormDiscoverer) Name() string {
	return "form"
}

// Discover extracts form parameters from the HTML response.
func (f *FormDiscoverer) Discover(_ context.Context, _ string, resp *http.Response) ([]core.Parameter, error) {
	if resp == nil || resp.Body == "" {
		return nil, nil
	}

	doc, err := html.Parse(strings.NewReader(resp.Body))
	if err != nil {
		return nil, nil // Not HTML, skip gracefully
	}

	var params []core.Parameter
	f.walkNode(doc, "", &params)
	return params, nil
}

// walkNode traverses the HTML tree to find form elements.
func (f *FormDiscoverer) walkNode(n *html.Node, formMethod string, params *[]core.Parameter) {
	if n.Type == html.ElementNode {
		switch n.Data {
		case "form":
			formMethod = f.getAttr(n, "method")
			// Process child elements within this form
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				f.walkNode(c, formMethod, params)
			}
			return // Don't recurse again below
		case "input":
			name := f.getAttr(n, "name")
			inputType := strings.ToLower(f.getAttr(n, "type"))
			if name != "" && inputType != "file" && inputType != "submit" && inputType != "button" && inputType != "image" && inputType != "reset" {
				*params = append(*params, core.Parameter{
					Name:     name,
					Location: f.locationForMethod(formMethod),
					Value:    f.getAttr(n, "value"),
					Type:     "string",
				})
			}
		case "textarea":
			name := f.getAttr(n, "name")
			if name != "" {
				*params = append(*params, core.Parameter{
					Name:     name,
					Location: f.locationForMethod(formMethod),
					Value:    f.textContent(n),
					Type:     "string",
				})
			}
		case "select":
			name := f.getAttr(n, "name")
			if name != "" {
				*params = append(*params, core.Parameter{
					Name:     name,
					Location: f.locationForMethod(formMethod),
					Value:    "",
					Type:     "string",
				})
			}
		}
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		f.walkNode(c, formMethod, params)
	}
}

// locationForMethod returns the parameter location based on the form method.
func (f *FormDiscoverer) locationForMethod(method string) string {
	if strings.EqualFold(method, "post") {
		return core.ParamLocationBody
	}
	return core.ParamLocationQuery
}

// getAttr returns the value of the named attribute.
func (f *FormDiscoverer) getAttr(n *html.Node, name string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, name) {
			return a.Val
		}
	}
	return ""
}

// textContent returns the text content of a node.
func (f *FormDiscoverer) textContent(n *html.Node) string {
	if n.Type == html.TextNode {
		return n.Data
	}
	var sb strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		sb.WriteString(f.textContent(c))
	}
	return sb.String()
}

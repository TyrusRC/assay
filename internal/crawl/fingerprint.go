// Package crawl implements a state-aware crawler. Unlike a plain breadth-first
// crawl that dedups by URL, it dedups expansion by a structural *state
// fingerprint* — the shape of the actions a page offers (its links and forms).
// Two different URLs that render the same state are expanded once, and the same
// URL that renders different states (e.g. logged-out vs logged-in) is treated
// as distinct states worth exploring. This reaches endpoints that only become
// reachable after a state transition, in the spirit of state-aware black-box
// scanning (cf. "Enemy of the State").
package crawl

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"golang.org/x/net/html"
)

// Form is a normalized HTML form: its submission target, method, and the names
// of its inputs. These define part of a page's action shape.
type Form struct {
	Action string
	Method string
	Fields []string
}

// Fingerprint returns a stable hash of a page's structural state: the sorted
// set of link paths plus the sorted set of form signatures. Visible text, link
// order, and the page title are deliberately ignored so cosmetic differences do
// not fragment the state space.
func Fingerprint(htmlBody string) string {
	links := extractLinks(htmlBody)
	paths := make([]string, 0, len(links))
	for _, l := range links {
		paths = append(paths, normalizePath(l))
	}
	sort.Strings(paths)
	paths = dedupSorted(paths)

	forms := extractForms(htmlBody)
	formSigs := make([]string, 0, len(forms))
	for _, f := range forms {
		fields := append([]string(nil), f.Fields...)
		sort.Strings(fields)
		formSigs = append(formSigs, f.Method+" "+normalizePath(f.Action)+" ["+strings.Join(fields, ",")+"]")
	}
	sort.Strings(formSigs)

	h := sha256.New()
	h.Write([]byte(strings.Join(paths, "\n")))
	h.Write([]byte("\x00forms\x00"))
	h.Write([]byte(strings.Join(formSigs, "\n")))
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// extractLinks returns the raw href values of anchor tags that have one.
func extractLinks(htmlBody string) []string {
	doc, err := html.Parse(strings.NewReader(htmlBody))
	if err != nil {
		return nil
	}
	var links []string
	walk(doc, func(n *html.Node) {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "a") {
			if href, ok := attrValue(n, "href"); ok && strings.TrimSpace(href) != "" {
				links = append(links, href)
			}
		}
	})
	return links
}

// extractForms returns the normalized forms in the document.
func extractForms(htmlBody string) []Form {
	doc, err := html.Parse(strings.NewReader(htmlBody))
	if err != nil {
		return nil
	}
	var forms []Form
	walk(doc, func(n *html.Node) {
		if n.Type != html.ElementNode || !strings.EqualFold(n.Data, "form") {
			return
		}
		f := Form{Method: "GET"}
		if a, ok := attrValue(n, "action"); ok {
			f.Action = a
		}
		if m, ok := attrValue(n, "method"); ok && strings.TrimSpace(m) != "" {
			f.Method = strings.ToUpper(strings.TrimSpace(m))
		}
		walk(n, func(c *html.Node) {
			if c.Type == html.ElementNode && (strings.EqualFold(c.Data, "input") ||
				strings.EqualFold(c.Data, "select") || strings.EqualFold(c.Data, "textarea")) {
				if name, ok := attrValue(c, "name"); ok && name != "" {
					f.Fields = append(f.Fields, name)
				}
			}
		})
		forms = append(forms, f)
	})
	return forms
}

// normalizePath reduces a URL or href to a comparable path: scheme/host/query/
// fragment are dropped and a trailing slash is trimmed (except for root).
func normalizePath(raw string) string {
	s := raw
	if i := strings.Index(s, "://"); i >= 0 {
		rest := s[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			s = rest[j:]
		} else {
			s = "/"
		}
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 1 {
		s = strings.TrimRight(s, "/")
	}
	if s == "" {
		s = "/"
	}
	return s
}

// attrValue returns the value of the named attribute and whether it was present.
func attrValue(n *html.Node, name string) (string, bool) {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, name) {
			return a.Val, true
		}
	}
	return "", false
}

// walk invokes fn on n and all descendants.
func walk(n *html.Node, fn func(*html.Node)) {
	fn(n)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walk(c, fn)
	}
}

// dedupSorted removes adjacent duplicates from a sorted slice.
func dedupSorted(s []string) []string {
	if len(s) == 0 {
		return s
	}
	out := s[:1]
	for _, v := range s[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

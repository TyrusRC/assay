// Package tabnabbing detects reverse-tabnabbing exposure: HTML pages
// that contain `<a target="_blank">` links without `rel="noopener"` (or
// `rel="noreferrer"`). Without those rel-attributes, the linked-to
// page can rewrite `window.opener.location` and silently navigate the
// original tab to a phishing URL.
//
// This is a static-HTML scan — fetch the page, parse anchor tags via
// golang.org/x/net/html, and emit one finding per offending link.
// We deduplicate by destination so a page with 50 links to the same
// site only yields one finding.
package tabnabbing

import (
	"context"
	"fmt"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
	"golang.org/x/net/html"
)

// Detector probes targetURL's HTML for unsafe anchor links.
type Detector struct {
	client *skwshttp.Client
}

// New returns a Detector wired to the project's shared HTTP client.
func New(client *skwshttp.Client) *Detector {
	return &Detector{client: client}
}

// Result carries findings from Detect.
type Result struct {
	Findings []*core.Finding
}

// Detect fetches targetURL and parses every <a> tag. An anchor that
// declares `target="_blank"` (or `target="<custom>"`) AND lacks both
// `rel="noopener"` and `rel="noreferrer"` is the reverse-tabnabbing
// vector. Same-host destinations are skipped — same-origin opener
// access is not the bug.
func (d *Detector) Detect(ctx context.Context, targetURL string) (*Result, error) {
	res := &Result{}
	if d.client == nil {
		return res, nil
	}
	resp, err := d.client.Get(ctx, targetURL)
	if err != nil || resp == nil {
		return res, nil
	}
	if !strings.Contains(strings.ToLower(resp.ContentType), "text/html") {
		return res, nil
	}
	doc, err := html.Parse(strings.NewReader(resp.Body))
	if err != nil {
		return res, nil
	}

	seen := make(map[string]bool)
	for href := range walkUnsafeLinks(doc) {
		if seen[href] {
			continue
		}
		seen[href] = true
		res.Findings = append(res.Findings, buildFinding(targetURL, href))
	}
	return res, nil
}

// walkUnsafeLinks streams every offending anchor href into a channel.
// Channel is buffered to len(links); we never block the caller.
func walkUnsafeLinks(root *html.Node) map[string]struct{} {
	out := make(map[string]struct{})
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "a") {
			if href, unsafe := evaluateAnchor(n); unsafe && href != "" {
				out[href] = struct{}{}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return out
}

// evaluateAnchor returns (href, unsafe). An anchor is "unsafe" when it
// opens a new browsing context (target attribute set, anything other
// than _self) AND its rel attribute does not include noopener or
// noreferrer.
func evaluateAnchor(n *html.Node) (string, bool) {
	var href, target, rel string
	for _, attr := range n.Attr {
		switch strings.ToLower(attr.Key) {
		case "href":
			href = attr.Val
		case "target":
			target = attr.Val
		case "rel":
			rel = attr.Val
		}
	}
	if href == "" {
		return "", false
	}
	t := strings.ToLower(strings.TrimSpace(target))
	if t == "" || t == "_self" || t == "_top" || t == "_parent" {
		return "", false
	}
	r := strings.ToLower(rel)
	if strings.Contains(r, "noopener") || strings.Contains(r, "noreferrer") {
		return "", false
	}
	// Skip mailto / tel / javascript / fragment-only — they cannot
	// host attacker JS.
	hl := strings.ToLower(href)
	if strings.HasPrefix(hl, "mailto:") || strings.HasPrefix(hl, "tel:") ||
		strings.HasPrefix(hl, "javascript:") || strings.HasPrefix(hl, "#") {
		return "", false
	}
	return href, true
}

func buildFinding(targetURL, href string) *core.Finding {
	finding := core.NewFinding("Reverse Tabnabbing (target=_blank without rel=noopener)", core.SeverityLow)
	finding.URL = targetURL
	finding.Parameter = href
	finding.Tool = "tabnabbing"
	finding.Confidence = core.ConfidenceHigh
	finding.Description = fmt.Sprintf(
		"Anchor pointing to %s opens a new browsing context but does not set rel=\"noopener\" (or noreferrer). The destination page can rewrite `window.opener.location` and redirect the original tab to a phishing URL without the user's knowledge.",
		href,
	)
	finding.Evidence = "Offending href: " + href + "\nMissing rel attribute: noopener / noreferrer"
	finding.Remediation = "Add `rel=\"noopener noreferrer\"` to every `<a target=\"_blank\">` link. Modern browsers default-imply noopener but older tabs and embedded webviews do not."
	finding.WithOWASPMapping(
		[]string{"WSTG-CLNT-13"},
		[]string{"A05:2025"},
		[]string{"CWE-1022"},
	)
	return finding
}

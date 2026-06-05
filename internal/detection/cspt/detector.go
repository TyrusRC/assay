package cspt

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
	assayhttp "github.com/TyrusRC/assay/internal/http"
	"golang.org/x/net/html"
)

// maxExternalScripts caps how many linked scripts a single page fetch will
// pull, bounding work on script-heavy pages.
const maxExternalScripts = 20

// Detector scans a page's inline and linked JavaScript for CSPT sinks.
type Detector struct {
	client *assayhttp.Client
}

// New returns a Detector wired to the project's shared HTTP client.
func New(client *assayhttp.Client) *Detector {
	return &Detector{client: client}
}

// Result carries findings from Detect.
type Result struct {
	Findings []*core.Finding
}

// Detect fetches targetURL, gathers its inline and same-document linked
// scripts, and reports a finding for each CSPT sink found.
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

	inline, srcs := collectScripts(doc)
	seen := make(map[string]bool)
	d.scan(targetURL, inline, "(inline)", seen, res)

	for i, src := range srcs {
		if i >= maxExternalScripts {
			break
		}
		abs := resolveScriptURL(targetURL, src)
		js := d.fetchScript(ctx, abs)
		if js == "" {
			continue
		}
		d.scan(targetURL, js, abs, seen, res)
	}
	return res, nil
}

// scan analyzes one script body and appends deduplicated findings.
func (d *Detector) scan(targetURL, js, origin string, seen map[string]bool, res *Result) {
	for _, sink := range Analyze(js) {
		key := origin + "|" + sink.Snippet
		if seen[key] {
			continue
		}
		seen[key] = true
		res.Findings = append(res.Findings, buildFinding(targetURL, origin, sink))
	}
}

// fetchScript retrieves a linked script body, returning "" on any error.
func (d *Detector) fetchScript(ctx context.Context, scriptURL string) string {
	resp, err := d.client.Get(ctx, scriptURL)
	if err != nil || resp == nil {
		return ""
	}
	return resp.Body
}

// collectScripts walks the parsed document and returns inline script text
// (concatenated) plus the list of external script-src URLs.
func collectScripts(root *html.Node) (inline string, srcs []string) {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "script") {
			if src, ok := attr(n, "src"); ok && src != "" {
				srcs = append(srcs, src)
			} else if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
				b.WriteString(n.FirstChild.Data)
				b.WriteString("\n")
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return b.String(), srcs
}

// attr returns the value of the named attribute and whether it was present.
func attr(n *html.Node, name string) (string, bool) {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, name) {
			return a.Val, true
		}
	}
	return "", false
}

// resolveScriptURL resolves a (possibly relative) script src against the page.
func resolveScriptURL(pageURL, src string) string {
	base, err := url.Parse(pageURL)
	if err != nil {
		return src
	}
	ref, err := url.Parse(src)
	if err != nil {
		return src
	}
	return base.ResolveReference(ref).String()
}

// buildFinding constructs the CSPT finding for one sink.
func buildFinding(targetURL, origin string, sink Sink) *core.Finding {
	f := core.NewFinding("Client-Side Path Traversal", core.SeverityMedium)
	f.At(targetURL, "").ByTool("cspt")
	f.Confidence = core.ConfidenceLow
	f.Title = "Client-Side Path Traversal sink in JavaScript"
	f.Description = fmt.Sprintf(
		"A %s call builds its request path from the attacker-influenced source %q. "+
			"Injecting ../ into that value can redirect the authenticated request to a "+
			"different same-origin endpoint, the primitive behind cache-deception and "+
			"account-takeover chains.", sink.Call, sink.Source)
	f.Evidence = fmt.Sprintf("script: %s\nsink: %s", origin, sink.Snippet)
	f.CWE = []string{"CWE-22"}
	f.WSTG = []string{"WSTG-CLNT-02"}
	f.Top10 = []string{"A01:2025"}
	f.Remediation = "Do not concatenate untrusted input into request paths. Validate/allow-list " +
		"the value, encode path segments, or resolve against a fixed base and reject traversal sequences."
	f.References = []string{
		"https://hacktricks.wiki/en/pentesting-web/client-side-path-traversal.html",
		"https://zere.es/posts/cache-deception-cspt-account-takeover/",
	}
	return f
}

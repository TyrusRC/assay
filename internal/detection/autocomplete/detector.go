// Package autocomplete checks password fields for autocomplete settings (WSTG-ATHN-05).
package autocomplete

import (
	"context"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
	"golang.org/x/net/html"
)

type Detector struct {
	client *http.Client
}

func New(client *http.Client) *Detector { return &Detector{client: client} }

func (d *Detector) Detect(ctx context.Context, targetURL string) ([]*core.Finding, error) {
	resp, err := d.client.Get(ctx, targetURL)
	if err != nil || resp == nil || resp.Body == "" {
		return nil, err
	}

	doc, err := html.Parse(strings.NewReader(resp.Body))
	if err != nil {
		return nil, nil
	}

	var findings []*core.Finding
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			inputType := attrVal(n, "type")
			if strings.EqualFold(inputType, "password") {
				ac := strings.ToLower(attrVal(n, "autocomplete"))
				if ac != "off" && ac != "new-password" && ac != "current-password" {
					f := core.NewFinding("Password Autocomplete Enabled", core.SeverityLow).At(targetURL, attrVal(n, "name"))
					f.Description = "Password field does not set autocomplete=\"off\" or autocomplete=\"new-password\". Browsers may cache the password."
					f.Tool = "autocomplete-detector"
					f.Confidence = core.ConfidenceHigh
					f.Remediation = "Add autocomplete=\"new-password\" (registration) or autocomplete=\"current-password\" (login) to password inputs."
					f.WithOWASPMapping([]string{"WSTG-ATHN-05"}, []string{"A04:2025"}, []string{"CWE-525"})
					findings = append(findings, f)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return findings, nil
}

func attrVal(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}

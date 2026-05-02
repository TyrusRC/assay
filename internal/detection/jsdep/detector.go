package jsdep

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// Detector finds JS libraries on a target page (via <script src=...>) and
// queries NVD for CVEs affecting their declared versions.
type Detector struct {
	client *skwshttp.Client
	nvd    *NVDClient
}

// New creates a Detector wired to the project's shared HTTP client and a
// fresh NVD client. apiKey may be empty; callers usually pass
// os.Getenv("NVD_API_KEY") at construction time.
func New(client *skwshttp.Client, apiKey string) *Detector {
	return &Detector{
		client: client,
		nvd:    NewNVDClient(apiKey),
	}
}

// WithNVD lets callers (and tests) inject a custom NVD client — pointed
// at an httptest.Server when fixturing.
func (d *Detector) WithNVD(c *NVDClient) *Detector {
	d.nvd = c
	return d
}

// Result carries the libraries we identified and the findings emitted.
type Result struct {
	Libraries []Library
	Findings  []*core.Finding
}

// scriptSrcRe matches an HTML `<script ... src="..." ...>` tag and
// captures the src value. Single- and double-quoted forms are supported.
// Bare-attribute (unquoted) src is rare in modern HTML and skipped — its
// regex tends to over-match.
var scriptSrcRe = regexp.MustCompile(`(?is)<script[^>]+src\s*=\s*(?:"([^"]+)"|'([^']+)')`)

// Detect fetches targetURL, extracts every <script src>, identifies any
// known libraries by version, and queries NVD for matching CVEs. One
// finding is emitted per (library, CVE) pair so reports cite each
// vulnerability discretely. A best-effort failure mode: if NVD is
// unreachable we still return the detected libraries so the caller knows
// the inventory.
func (d *Detector) Detect(ctx context.Context, targetURL string) (*Result, error) {
	res := &Result{}
	if d.client == nil {
		return res, nil
	}

	resp, err := d.client.Get(ctx, targetURL)
	if err != nil || resp == nil {
		return res, nil
	}

	base, _ := url.Parse(targetURL)
	scripts := extractScriptSrcs(resp.Body, base)

	seen := make(map[string]bool) // dedupe libraries by name+version
	for _, s := range scripts {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}
		lib := IdentifyLibrary(s)
		if lib == nil {
			continue
		}
		key := lib.Name + "@" + lib.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		res.Libraries = append(res.Libraries, *lib)

		cpe := CPEName(lib.CPEVendor, lib.CPEProduct, lib.Version)
		cves, _ := d.nvd.FindByCPE(ctx, cpe)
		for _, c := range cves {
			res.Findings = append(res.Findings, buildFinding(targetURL, *lib, cpe, c))
		}
	}
	return res, nil
}

// extractScriptSrcs returns every script src in body, resolved against
// base. Relative URLs become absolute so callers (and IdentifyLibrary)
// see consistent input.
func extractScriptSrcs(body string, base *url.URL) []string {
	var out []string
	for _, m := range scriptSrcRe.FindAllStringSubmatch(body, -1) {
		raw := m[1]
		if raw == "" {
			raw = m[2]
		}
		if raw == "" {
			continue
		}
		if base != nil {
			if u, err := base.Parse(raw); err == nil {
				out = append(out, u.String())
				continue
			}
		}
		out = append(out, raw)
	}
	return out
}

func buildFinding(targetURL string, lib Library, cpe string, cve CVE) *core.Finding {
	severity := mapSeverity(cve.Severity)
	finding := core.NewFinding(fmt.Sprintf("Vulnerable JS Dependency (%s)", lib.Name), severity)
	finding.URL = targetURL
	finding.Tool = "jsdep-nvd"
	finding.Confidence = core.ConfidenceHigh
	finding.Description = fmt.Sprintf(
		"%s %s on this page is affected by %s. %s",
		lib.Name, lib.Version, cve.ID, strings.TrimSpace(cve.Description),
	)
	finding.Evidence = fmt.Sprintf(
		"Library: %s %s\nLoaded from: %s\nCPE: %s\nCVE: %s (CVSS %.1f, %s)",
		lib.Name, lib.Version, lib.ScriptURL, cpe, cve.ID, cve.CVSS, cve.Severity,
	)
	finding.Remediation = fmt.Sprintf(
		"Upgrade %s to a non-vulnerable release. Audit your dependency manifest (package.json / bower / vendored copies) so the upgrade does not regress on the next deploy.",
		lib.Name,
	)
	finding.WithOWASPMapping(
		[]string{"WSTG-CONF-09"},
		[]string{"A06:2025"},
		[]string{"CWE-1104"},
	)
	finding.References = []string{
		"https://nvd.nist.gov/vuln/detail/" + cve.ID,
	}
	finding.CVSS = cve.CVSS
	return finding
}

// mapSeverity converts NVD's CVSS baseSeverity to the project's
// core.Severity. Unknown strings default to Medium so we don't drop
// findings on the floor.
func mapSeverity(nvdSeverity string) core.Severity {
	switch strings.ToUpper(nvdSeverity) {
	case "CRITICAL":
		return core.SeverityCritical
	case "HIGH":
		return core.SeverityHigh
	case "MEDIUM":
		return core.SeverityMedium
	case "LOW":
		return core.SeverityLow
	default:
		return core.SeverityMedium
	}
}

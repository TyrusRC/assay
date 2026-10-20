package xss

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

// StoredDetector performs stored XSS detection via inject→crawl→match→confirm.
type StoredDetector struct {
	client  *http.Client
	verbose bool
}

// NewStoredDetector creates a stored XSS detector.
func NewStoredDetector(client *http.Client) *StoredDetector {
	return &StoredDetector{client: client}
}

// WithVerbose enables verbose output.
func (d *StoredDetector) WithVerbose(v bool) *StoredDetector {
	d.verbose = v
	return d
}

// StoredDetectOptions configures stored XSS detection.
type StoredDetectOptions struct {
	MaxCrawlPages int
	CrawlDepth    int
	Timeout       time.Duration
}

// DefaultStoredOptions returns sensible defaults.
func DefaultStoredOptions() StoredDetectOptions {
	return StoredDetectOptions{
		MaxCrawlPages: 30,
		CrawlDepth:    2,
		Timeout:       10 * time.Second,
	}
}

type canaryRecord struct {
	Canary    string
	TargetURL string
	Param     string
	Method    string
}

type reflectionHit struct {
	canaryRecord
	ReflectionURL string
	Context       string // snippet around the canary
}

// DetectStored runs the inject→crawl→match→confirm cycle for stored XSS.
func (d *StoredDetector) DetectStored(ctx context.Context, targetURL string, params []core.Parameter, method string, opts StoredDetectOptions) []*core.Finding {
	if len(params) == 0 {
		return nil
	}

	// Phase 1: Inject unique canary strings into each parameter.
	canaries := d.injectCanaries(ctx, targetURL, params, method)
	if len(canaries) == 0 {
		return nil
	}

	// Phase 2: Crawl linked pages to find where canaries surfaced.
	hits := d.crawlForCanaries(ctx, targetURL, canaries, opts)
	if len(hits) == 0 {
		return nil
	}

	// Phase 3: Confirm with real XSS payload at each reflection point.
	return d.confirmXSS(ctx, hits, method)
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (d *StoredDetector) injectCanaries(ctx context.Context, targetURL string, params []core.Parameter, method string) []canaryRecord {
	var canaries []canaryRecord

	for _, p := range params {
		select {
		case <-ctx.Done():
			return canaries
		default:
		}

		if p.Location != core.ParamLocationQuery && p.Location != core.ParamLocationBody {
			continue
		}

		canary := "assayxss" + randomHex(4)
		_, err := d.client.SendPayload(ctx, targetURL, p.Name, canary, method)
		if err != nil {
			continue
		}

		canaries = append(canaries, canaryRecord{
			Canary:    canary,
			TargetURL: targetURL,
			Param:     p.Name,
			Method:    method,
		})
	}

	return canaries
}

func (d *StoredDetector) crawlForCanaries(ctx context.Context, targetURL string, canaries []canaryRecord, opts StoredDetectOptions) []reflectionHit {
	// Collect URLs to check: the target itself + linked pages up to CrawlDepth.
	toVisit := d.gatherURLs(ctx, targetURL, opts)

	var hits []reflectionHit
	visited := 0

	for _, pageURL := range toVisit {
		if visited >= opts.MaxCrawlPages {
			break
		}
		select {
		case <-ctx.Done():
			return hits
		default:
		}

		resp, err := d.client.Get(ctx, pageURL)
		if err != nil || resp == nil {
			continue
		}
		visited++

		for _, c := range canaries {
			idx := strings.Index(resp.Body, c.Canary)
			if idx < 0 {
				continue
			}

			// Extract context around the canary.
			start := idx - 80
			if start < 0 {
				start = 0
			}
			end := idx + len(c.Canary) + 80
			if end > len(resp.Body) {
				end = len(resp.Body)
			}
			snippet := resp.Body[start:end]

			hits = append(hits, reflectionHit{
				canaryRecord:  c,
				ReflectionURL: pageURL,
				Context:       snippet,
			})
		}
	}

	return hits
}

func (d *StoredDetector) gatherURLs(ctx context.Context, targetURL string, opts StoredDetectOptions) []string {
	seen := map[string]bool{targetURL: true}
	result := []string{targetURL}
	frontier := []string{targetURL}

	for depth := 0; depth < opts.CrawlDepth && len(frontier) > 0; depth++ {
		var next []string
		for _, u := range frontier {
			select {
			case <-ctx.Done():
				return result
			default:
			}
			if len(result) >= opts.MaxCrawlPages {
				return result
			}

			resp, err := d.client.Get(ctx, u)
			if err != nil || resp == nil {
				continue
			}

			links := extractSimpleLinks(resp.Body, u)
			base := baseHost(targetURL)
			for _, link := range links {
				if seen[link] || !sameHost(link, base) {
					continue
				}
				seen[link] = true
				result = append(result, link)
				next = append(next, link)
			}
		}
		frontier = next
	}

	return result
}

func (d *StoredDetector) confirmXSS(ctx context.Context, hits []reflectionHit, method string) []*core.Finding {
	var findings []*core.Finding

	xssPayloads := []struct {
		payload string
		marker  string
	}{
		{`"><img src=x onerror=assayxssconfirm>`, `onerror=assayxssconfirm`},
		{`<script>assayxssconfirm</script>`, `<script>assayxssconfirm</script>`},
		{`'><svg/onload=assayxssconfirm>`, `onload=assayxssconfirm`},
	}

	confirmed := map[string]bool{}

	for _, hit := range hits {
		key := hit.TargetURL + "|" + hit.Param + "|" + hit.ReflectionURL
		if confirmed[key] {
			continue
		}

		for _, xp := range xssPayloads {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			// Re-inject with XSS payload.
			_, err := d.client.SendPayload(ctx, hit.TargetURL, hit.Param, xp.payload, method)
			if err != nil {
				continue
			}

			// Re-visit the reflection page.
			resp, err := d.client.Get(ctx, hit.ReflectionURL)
			if err != nil || resp == nil {
				continue
			}

			if strings.Contains(resp.Body, xp.marker) {
				finding := core.NewFinding("stored-xss", core.SeverityHigh).
					At(hit.TargetURL, hit.Param)
				finding.Tool = "stored-xss-detector"
				finding.Confidence = core.ConfidenceHigh
				finding.Title = fmt.Sprintf("Stored XSS via %s on %s reflected at %s",
					hit.Param, hit.TargetURL, hit.ReflectionURL)
				finding.Description = fmt.Sprintf(
					"Input injected into parameter %q at %s is stored and rendered unescaped at %s. "+
						"The XSS payload %q was confirmed in the page body.",
					hit.Param, hit.TargetURL, hit.ReflectionURL, xp.payload,
				)
				finding.Evidence = xp.marker
				finding.Verified = true

				body := resp.Body
				if len(body) > 500 {
					body = body[:500] + "..."
				}
				finding.Response = body

				finding.WithOWASPMapping(
					[]string{"WSTG-INPV-02"},
					[]string{"A03:2021"},
					[]string{"CWE-79"},
				)
				finding.Remediation = "Encode all user-supplied output using context-appropriate encoding (HTML entity, JS, URL). Use Content-Security-Policy to mitigate impact."

				findings = append(findings, finding)
				confirmed[key] = true
				break
			}
		}
	}

	return findings
}

// extractSimpleLinks pulls href values from <a> tags. Lightweight — no full HTML parse.
func extractSimpleLinks(body, baseURL string) []string {
	var links []string
	base, err := url.Parse(baseURL)
	if err != nil {
		return links
	}

	lower := strings.ToLower(body)
	search := `href="`
	for {
		idx := strings.Index(lower, search)
		if idx < 0 {
			break
		}
		start := idx + len(search)
		end := strings.IndexByte(body[start:], '"')
		if end < 0 {
			break
		}
		raw := body[start : start+end]
		lower = lower[start+end:]
		body = body[start+end:]

		if strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "mailto:") {
			continue
		}

		ref, err := url.Parse(raw)
		if err != nil {
			continue
		}
		resolved := base.ResolveReference(ref).String()
		links = append(links, resolved)
	}
	return links
}

func baseHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func sameHost(rawURL, host string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Hostname(), host)
}

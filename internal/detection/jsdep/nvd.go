package jsdep

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// NVDClient queries the NVD CVE API v2 by CPE name. The default endpoint
// is the public NVD service; tests inject an httptest URL via the
// Endpoint field. APIKey is optional — without it NVD allows ~5 req/30s,
// with it ~50 req/30s.
//
// MinInterval is the minimum gap between consecutive requests; the client
// sleeps as needed to respect it. Default values are picked by
// NewNVDClient based on whether an API key is set (anonymous: 6s,
// authenticated: 600ms). Tests can zero it out for instant runs.
type NVDClient struct {
	Endpoint    string
	APIKey      string
	HTTPClient  *http.Client
	MinInterval time.Duration

	mu      sync.Mutex
	lastReq time.Time
}

// DefaultNVDEndpoint is the v2 CVE search endpoint.
const DefaultNVDEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// NewNVDClient returns a client with a 10s HTTP timeout and the right
// pacing for the chosen tier. apiKey may be empty (public tier ~5
// req/30s → 6s gap); a non-empty key uses the authenticated tier (~50
// req/30s → 600ms gap). Both stay safely under NVD's published limits.
func NewNVDClient(apiKey string) *NVDClient {
	interval := 6 * time.Second
	if apiKey != "" {
		interval = 600 * time.Millisecond
	}
	return &NVDClient{
		Endpoint:    DefaultNVDEndpoint,
		APIKey:      apiKey,
		HTTPClient:  &http.Client{Timeout: 10 * time.Second},
		MinInterval: interval,
	}
}

// HasAPIKey reports whether the client is using the authenticated tier.
// Useful for one-line verbose-log messages so users know which limit
// they're scanning under.
func (c *NVDClient) HasAPIKey() bool {
	return c.APIKey != ""
}

// throttle blocks until at least MinInterval has elapsed since the last
// outbound request. The lock is held only across the time math, so
// concurrent callers serialise rather than race on lastReq. ctx
// cancellation aborts the wait early.
func (c *NVDClient) throttle(ctx context.Context) error {
	if c.MinInterval <= 0 {
		return nil
	}
	c.mu.Lock()
	wait := time.Duration(0)
	if !c.lastReq.IsZero() {
		elapsed := time.Since(c.lastReq)
		if elapsed < c.MinInterval {
			wait = c.MinInterval - elapsed
		}
	}
	c.lastReq = time.Now().Add(wait)
	c.mu.Unlock()

	if wait <= 0 {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// CVE is a denormalised view of one NVD record, carrying only the fields
// we surface in findings. Severity strings are normalised to NVD's
// CVSS v3 baseSeverity ("CRITICAL"|"HIGH"|"MEDIUM"|"LOW"); UNKNOWN is
// returned when no v3 metric is present.
type CVE struct {
	ID          string
	Description string
	CVSS        float64
	Severity    string
}

// FindByCPE queries NVD for CVEs that affect the given CPE 2.3 name.
// Empty results (or an HTTP error) return ([], nil) rather than an error,
// because failing the whole scan over an unreachable third-party API is
// strictly worse than reporting "no CVE info available" — every other
// detector still produces value.
func (c *NVDClient) FindByCPE(ctx context.Context, cpeName string) ([]CVE, error) {
	if cpeName == "" {
		return nil, nil
	}

	if err := c.throttle(ctx); err != nil {
		return nil, err
	}

	q := url.Values{}
	q.Set("cpeName", cpeName)
	reqURL := c.Endpoint + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build NVD request: %w", err)
	}
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, nil
	}

	var raw nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, nil
	}
	return parseCVEs(&raw), nil
}

// CPEName builds a CPE 2.3 application name from the standard
// `cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*` template.
// Components are URL-safe characters by spec; we trust callers to pass
// vendor/product strings sourced from libraryRules above.
func CPEName(vendor, product, version string) string {
	if vendor == "" || product == "" || version == "" {
		return ""
	}
	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, version)
}

// nvdResponse mirrors only the fields we extract; NVD's full schema is
// far larger and changes over time, so we narrowly project into typed
// fields. Anything we don't read is ignored by the JSON decoder.
type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CVSSMetricV31 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CVSSMetricV30 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func parseCVEs(raw *nvdResponse) []CVE {
	out := make([]CVE, 0, len(raw.Vulnerabilities))
	for _, v := range raw.Vulnerabilities {
		desc := ""
		for _, d := range v.CVE.Descriptions {
			if strings.EqualFold(d.Lang, "en") {
				desc = d.Value
				break
			}
		}
		score, sev := 0.0, "UNKNOWN"
		if len(v.CVE.Metrics.CVSSMetricV31) > 0 {
			score = v.CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
			sev = v.CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity
		} else if len(v.CVE.Metrics.CVSSMetricV30) > 0 {
			score = v.CVE.Metrics.CVSSMetricV30[0].CVSSData.BaseScore
			sev = v.CVE.Metrics.CVSSMetricV30[0].CVSSData.BaseSeverity
		}
		out = append(out, CVE{
			ID:          v.CVE.ID,
			Description: desc,
			CVSS:        score,
			Severity:    sev,
		})
	}
	return out
}

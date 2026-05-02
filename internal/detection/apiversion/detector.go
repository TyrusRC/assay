// Package apiversion enumerates sibling versions of detected API paths
// (OWASP API9:2023 Improper Inventory Management). When the target URL
// contains a /vN/ segment we probe the same path under v0..vN+1, /legacy,
// /beta, /preview, and /internal and emit findings on any sibling that
// returns a different non-404 response. Older versions of the same API
// often lag on patches and ship deprecated bugs (auth bypass, mass
// assignment) that the current version has fixed.
package apiversion

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/analysis"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// versionSegmentRe matches the "/vN" path segment that announces a
// versioned REST API. Three-digit majors (Stripe-style /v2025) are
// excluded by the {1,3} bound to avoid year-tag false positives.
var versionSegmentRe = regexp.MustCompile(`/v(\d{1,3})(?:/|$)`)

// extraVersionTokens are non-numeric "version-like" siblings that often
// expose dev or staging surfaces in production.
var extraVersionTokens = []string{"v0", "legacy", "beta", "preview", "alpha", "internal", "private", "experimental"}

// Detector probes for sibling versions of the path prefix in targetURL.
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

// Detect inspects targetURL for a /vN/ path segment and probes siblings.
// No-op when targetURL has no version segment — mass-probing every URL
// for /v1/foo would flood reports.
func (d *Detector) Detect(ctx context.Context, targetURL string) (*Result, error) {
	res := &Result{}
	if d.client == nil {
		return res, nil
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return res, nil
	}

	loc := versionSegmentRe.FindStringSubmatchIndex(u.Path)
	if loc == nil {
		return res, nil // no version segment → no probe
	}

	// Slice of the matched "vN" without the slash; we substitute siblings here.
	versionStart, versionEnd := loc[2]-1, loc[3] // captures group 1 indices
	// Adjust to include the leading "v".
	versionStart = loc[0] + 1
	versionEnd = versionStart + len("v") + (loc[3] - loc[2])

	currentN, _ := strconv.Atoi(u.Path[loc[2]:loc[3]])

	// Capture the original response shape — we only flag siblings whose
	// body diverges from this. Same body across versions usually means
	// the route is shared (path-rewrite into the same handler).
	currentResp, err := d.client.Get(ctx, targetURL)
	if err != nil || currentResp == nil {
		return res, nil
	}
	currentStripped := analysis.StripDynamicContent(currentResp.Body)

	// Soft-404 baseline (random version, e.g. /v9-randomhex/).
	canaryURL := *u
	canaryURL.Path = u.Path[:versionStart] + "v" + randomBlob() + u.Path[versionEnd:]
	soft404Resp, _ := d.client.Get(ctx, canaryURL.String())
	soft404Body := ""
	soft404Status := 0
	if soft404Resp != nil {
		soft404Body = analysis.StripDynamicContent(soft404Resp.Body)
		soft404Status = soft404Resp.StatusCode
	}

	// Build sibling tokens.
	var siblings []string
	for n := 0; n <= currentN+1; n++ {
		if n == currentN {
			continue
		}
		siblings = append(siblings, "v"+strconv.Itoa(n))
	}
	siblings = append(siblings, extraVersionTokens...)

	seen := make(map[string]bool)
	for _, sib := range siblings {
		if seen[sib] {
			continue
		}
		seen[sib] = true

		probe := *u
		probe.Path = u.Path[:versionStart] + sib + u.Path[versionEnd:]
		probeURL := probe.String()

		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}

		resp, err := d.client.Get(ctx, probeURL)
		if err != nil || resp == nil {
			continue
		}
		// Ignore obvious negatives.
		if resp.StatusCode == 404 || resp.StatusCode == 410 {
			continue
		}
		// Ignore auth-controlled siblings — that means the gate is working.
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			continue
		}
		// Suppress soft-404s where the server returns the same body for
		// every unknown version.
		stripped := analysis.StripDynamicContent(resp.Body)
		if soft404Status != 0 && resp.StatusCode == soft404Status &&
			analysis.ResponseSimilarity(stripped, soft404Body) >= 0.95 {
			continue
		}
		// Suppress identical-body siblings — server is rewriting all
		// versions to the same handler.
		if analysis.ResponseSimilarity(stripped, currentStripped) >= 0.97 {
			continue
		}

		res.Findings = append(res.Findings, buildFinding(targetURL, probeURL, sib, resp))
	}

	return res, nil
}

func buildFinding(originalURL, probedURL, sibling string, resp *skwshttp.Response) *core.Finding {
	severity := core.SeverityMedium
	// Older numeric versions and "internal"/"legacy" rate higher.
	switch {
	case strings.HasPrefix(sibling, "v") && sibling != "v0":
		// Same major-1 sibling — Medium.
	case sibling == "internal", sibling == "private", sibling == "experimental":
		severity = core.SeverityHigh
	case sibling == "legacy", sibling == "v0", sibling == "alpha":
		severity = core.SeverityHigh
	}
	finding := core.NewFinding("Reachable Sibling API Version", severity)
	finding.URL = probedURL
	finding.Parameter = sibling
	finding.Tool = "apiversion"
	finding.Confidence = core.ConfidenceMedium
	finding.Description = fmt.Sprintf(
		"Sibling API version %q is reachable alongside the documented one. Older or non-public versions often lag on patches; an attacker who finds an unpatched sibling can sidestep fixes shipped on the current version.",
		sibling,
	)
	bodyLen := 0
	if resp != nil {
		bodyLen = len(resp.Body)
	}
	finding.Evidence = fmt.Sprintf("Original URL: %s\nSibling: %s\nStatus: %d\nResponse length: %d",
		originalURL, probedURL, resp.StatusCode, bodyLen)
	finding.Remediation = "Decommission deprecated API versions. If older versions must remain reachable for backwards compatibility, ensure they receive the same security patches as the current version, or front them with a gateway that proxies into the current handlers."
	finding.WithOWASPMapping(
		[]string{"WSTG-CONF-04"},
		[]string{"A05:2025"},
		[]string{"CWE-1059"},
	)
	finding.APITop10 = []string{"API9:2023"}
	return finding
}

func randomBlob() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

package oauthflow

import (
	"context"
	"fmt"
	"net/url"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

// DetectRedirectURIMatching probes the authorize endpoint with hostile
// `redirect_uri` variants derived from the registered URI. Per RFC 6749
// §3.1.2.2 and RFC 9700 §4.1, redirect_uri matching MUST be exact;
// suffix, prefix, or path-normalization matching enables open-redirect
// → code-leak → account-takeover chains.
func (d *Detector) DetectRedirectURIMatching(ctx context.Context, authzURL string, opts DetectOptions) (*DetectionResult, error) {
	ctx, cancel := withTimeout(ctx, opts)
	defer cancel()

	result := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: "redirect-uri-matching",
	}

	if opts.RegisteredRedirectURI == "" {
		return result, fmt.Errorf("RegisteredRedirectURI is required")
	}

	base, err := url.Parse(authzURL)
	if err != nil {
		return result, fmt.Errorf("parse authzURL: %w", err)
	}

	variants := extendedRedirectURIVariants(opts.RegisteredRedirectURI)
	for _, variant := range variants {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		probeURL := d.buildAuthzURL(base, opts, map[string]string{
			"redirect_uri": variant,
			"state":        "assay-redir-probe",
		}, true)

		resp, err := d.probe(ctx, probeURL)
		if err != nil || resp == nil {
			continue
		}
		if !d.redirectsToVariant(resp, variant) {
			continue
		}

		result.Findings = append(result.Findings, d.findingRedirectURIBypass(probeURL, variant, opts.RegisteredRedirectURI, resp))
		result.Vulnerable = true
		// One confirmed bypass is enough to prove the bug class; bail
		// out to avoid spamming findings for cousin variants.
		return result, nil
	}

	return result, nil
}

// redirectURIVariants derives a small fixed set of hostile variants
// from the registered URI. Each represents a distinct exact-match
// bypass technique observed in real bug bounty reports.
func redirectURIVariants(registered string) []string {
	u, err := url.Parse(registered)
	if err != nil || u.Host == "" {
		return nil
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}
	host := u.Host
	path := u.Path
	if path == "" {
		path = "/"
	}

	return []string{
		// Suffix-host bypass: many naïve regexes anchor on the
		// registered host as a prefix, so `app.example.com.attacker.com`
		// passes a `startsWith("app.example.com")` check.
		fmt.Sprintf("%s://%s.attacker.com%s", scheme, host, path),
		// Path traversal: `/cb/../redirect` normalizes to `/redirect`
		// on some IdPs and to `/cb/../redirect` (string match) on
		// others — either way it isn't the registered path.
		fmt.Sprintf("%s://%s%s/../redirect", scheme, host, path),
		// Open-redirect chain via query parameter: even with exact host
		// match, a trusting downstream `next=` redirect lets the
		// attacker pivot off-host.
		fmt.Sprintf("%s://%s%s?next=//attacker.com", scheme, host, path),
	}
}

// variantHost extracts the host portion of a probe variant for relaxed
// Location-header matching when the IdP normalizes the URI.
func variantHost(v string) string {
	u, err := url.Parse(v)
	if err != nil {
		return ""
	}
	return u.Host
}

// findingRedirectURIBypass flags acceptance of a non-exact-match
// redirect_uri variant.
func (d *Detector) findingRedirectURIBypass(probeURL, variant, registered string, resp *http.Response) *core.Finding {
	loc := resp.Headers["Location"]
	if loc == "" {
		loc = resp.Headers["location"]
	}
	f := core.NewFinding("OAuth redirect_uri Partial-Match Bypass", core.SeverityCritical)
	f.URL = probeURL
	f.Description = "The OAuth authorization endpoint accepted a `redirect_uri` that does not match " +
		"the registered URI byte-for-byte and emitted a 3xx redirecting toward the attacker-supplied " +
		"value. Per RFC 6749 §3.1.2.2 and RFC 9700 §4.1, redirect_uri matching MUST be exact; partial, " +
		"prefix, or path-normalized matching enables an attacker to exfiltrate the authorization code " +
		"to a host they control, completing full account takeover."
	f.Evidence = fmt.Sprintf("registered=%s; variant=%s; Location=%s; status=%d",
		registered, variant, loc, resp.StatusCode)
	f.Tool = toolName
	f.Confidence = core.ConfidenceConfirmed
	f.Remediation = "Compare the supplied `redirect_uri` byte-for-byte against the registered URI " +
		"after URL normalization. Reject prefix/suffix matching, path traversal, and query-string " +
		"appendage. Reject the request with 400 when the comparison fails; do NOT redirect."
	f.WithOWASPMapping(
		[]string{"WSTG-ATHZ-04"},
		[]string{"A07:2025"},
		[]string{"CWE-601"},
	)
	return f
}

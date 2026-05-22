package oauthflow

import (
	"context"
	"net/url"
	"strings"

	"github.com/TyrusRC/assay/internal/http"
)

// probe sends a GET with redirect-following disabled so the raw 3xx
// Location header (where OAuth flows surface their result) is visible.
func (d *Detector) probe(ctx context.Context, target string) (*http.Response, error) {
	client := d.client.Clone().WithFollowRedirects(false)
	return client.Get(ctx, target)
}

// buildAuthzURL composes an authorization-endpoint URL with a baseline
// set of parameters (response_type, client_id, redirect_uri, scope,
// state) and overlays the supplied overrides. When includeState is
// false, the state parameter is removed from the final URL even if the
// caller specified one — used by the "state omitted" probe.
func (d *Detector) buildAuthzURL(base *url.URL, opts DetectOptions, overrides map[string]string, includeState bool) string {
	u := *base
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", opts.clientID())
	if opts.RegisteredRedirectURI != "" {
		q.Set("redirect_uri", opts.RegisteredRedirectURI)
	}
	q.Set("scope", "openid")
	q.Set("state", "assay-state-default")
	for k, v := range overrides {
		q.Set(k, v)
	}
	if !includeState {
		q.Del("state")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// acceptsAuthorize reports whether the response looks like the IdP
// progressed the flow rather than rejecting it. A 2xx without `error=`
// in the body, or a 3xx whose Location lacks `error=` and `error_uri=`,
// counts as acceptance.
func (d *Detector) acceptsAuthorize(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Headers["Location"]
		if loc == "" {
			loc = resp.Headers["location"]
		}
		lower := strings.ToLower(loc)
		if strings.Contains(lower, "error=") || strings.Contains(lower, "error_uri=") {
			return false
		}
		return loc != ""
	}
	if resp.StatusCode == 200 {
		lower := strings.ToLower(resp.Body)
		if strings.Contains(lower, `"error"`) || strings.Contains(lower, "invalid_request") {
			return false
		}
		return true
	}
	return false
}

// redirectsToVariant returns true when the response is a 3xx whose
// Location header carries the hostile variant URI. This is the
// confirmation signal for redirect_uri exact-match bypass.
func (d *Detector) redirectsToVariant(resp *http.Response, variant string) bool {
	if resp == nil || resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return false
	}
	loc := resp.Headers["Location"]
	if loc == "" {
		loc = resp.Headers["location"]
	}
	if loc == "" {
		return false
	}
	// The IdP-emitted Location often URL-encodes the redirect_uri; match
	// both raw and decoded forms against the variant's host/path.
	decoded, _ := url.QueryUnescape(loc)
	target := strings.ToLower(variant)
	host := strings.ToLower(variantHost(variant))
	candidates := []string{strings.ToLower(loc), strings.ToLower(decoded)}
	for _, c := range candidates {
		if strings.Contains(c, target) {
			return true
		}
		if host != "" && strings.Contains(c, host) {
			return true
		}
	}
	return false
}

// tokenIssued reports whether a token-endpoint response represents a
// successful issuance. RFC 6749 §5 mandates 200 + JSON with
// access_token; servers that hand back access_token / id_token in any
// 2xx body count.
func (d *Detector) tokenIssued(resp *http.Response) bool {
	if resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}
	lower := strings.ToLower(resp.Body)
	if strings.Contains(lower, `"error"`) {
		return false
	}
	if strings.Contains(lower, `"access_token"`) || strings.Contains(lower, `"id_token"`) {
		return true
	}
	return false
}

package cachedeception

import (
	"net/url"
	"strings"
)

// cdnSessionSemicolon produces CDN-flavored session-id semicolon
// truncations: /account;jsessionid=poison, /account;PHPSESSID=poison,
// /account;CFID=poison, /account;CFTOKEN=poison. CDNs (Akamai's
// jsessionid-aware caching, Fastly's path-parameter normalization,
// Varnish's default vcl_recv) treat the entire ;... segment as
// non-keying, while most backend frameworks route to /account
// regardless.
func cdnSessionSemicolon(base *url.URL) []probeURL {
	path := strings.TrimSuffix(base.Path, "/")
	keys := []string{"jsessionid", "PHPSESSID", "CFID", "CFTOKEN", "sid", "JSESSIONIDSSO"}
	out := make([]probeURL, 0, len(keys))
	for _, k := range keys {
		out = append(out, probeURL{
			URL:      withRawPath(base, path+";"+k+"=assay-cdn-poison"),
			Strategy: StrategyCDNSessionSemicolon,
		})
	}
	return out
}

// cdnQueryStrip produces probes carrying query parameters that CDNs
// strip from the cache key but the backend may use to render
// different content: fbclid (Cloudflare/Fastly default-strip),
// __cf_chl_managed_tk__ (Cloudflare-only), utm_source / utm_medium
// (most CDNs strip via cache-key configuration).
func cdnQueryStrip(base *url.URL) []probeURL {
	params := []string{
		"fbclid",
		"__cf_chl_managed_tk__",
		"utm_source",
		"utm_medium",
		"gclid",
	}
	out := make([]probeURL, 0, len(params))
	for _, p := range params {
		cp := *base
		q := cp.Query()
		q.Set(p, "assay-cdn-poison")
		cp.RawQuery = q.Encode()
		out = append(out, probeURL{
			URL:      cp.String(),
			Strategy: StrategyCDNQueryStrip,
		})
	}
	return out
}

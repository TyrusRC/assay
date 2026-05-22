package cachedeception

import (
	"github.com/TyrusRC/assay/internal/core"
)

// DetectOptions configures a cache-deception probe.
type DetectOptions struct {
	// MaxProbes caps the deceptive URLs we try per target. The default
	// payload set is ~25 mutations; against a thoughtfully-routed app
	// most return immediately so the cap rarely binds.
	MaxProbes int
	// VerifyWithUnauth enables a second probe per matching deceptive URL
	// without auth cookies. When the cache served the authenticated body
	// to the unauth probe, the finding is promoted to Critical+Confirmed.
	VerifyWithUnauth bool
	// Extensions is the cacheable-extension list to mutate the path with.
	// Empty falls back to defaultExtensions.
	Extensions []string
	// Strategies enables/disables specific URL-mutation strategies.
	// Empty falls back to all strategies enabled.
	Strategies []ProbeStrategy
}

// DefaultOptions returns sane defaults: every strategy, every default
// extension, unauth verification enabled. Detectors that lack auth cookies
// will still benefit from the deceptive-URL probe but cannot confirm.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		MaxProbes:        50,
		VerifyWithUnauth: true,
	}
}

// ProbeStrategy is a URL-mutation family. Cache deception attacks come in
// families: append-extension is by far the most common, but path-traversal
// and delimiter-injection produce different hits depending on the
// framework/CDN combination.
type ProbeStrategy string

const (
	// StrategyAppendExtension produces /target.css, /target.js, etc.
	// Most common — works against any framework that route-matches before
	// looking at the file extension.
	StrategyAppendExtension ProbeStrategy = "append-extension"
	// StrategyPathSegment produces /target/foo.css, /target/index.css.
	// Hits frameworks that match by URL prefix (Express trailing-slash
	// handling, ASP.NET Core endpoint routing, Spring path patterns).
	StrategyPathSegment ProbeStrategy = "path-segment"
	// StrategySemicolonDelimiter produces /target;.css, /target;foo.css.
	// Apache/Tomcat strip everything after a semicolon when matching, but
	// the cache treats the full URL as the key.
	StrategySemicolonDelimiter ProbeStrategy = "semicolon-delimiter"
	// StrategyEncodedNull produces /target%00.css.
	// Some servers truncate at NUL; some caches preserve the raw URL.
	StrategyEncodedNull ProbeStrategy = "encoded-null"
	// StrategyTrailingSlash produces /target/.css, /target/.
	// Catches frameworks that normalize trailing slashes during routing
	// but not before the cache layer reads the key.
	StrategyTrailingSlash ProbeStrategy = "trailing-slash"
	// StrategyCDNSessionSemicolon produces /target;jsessionid=...,
	// /target;PHPSESSID=..., /target;cfid=.... CDNs (Akamai, Fastly,
	// Varnish in default vcl_recv) strip path-parameters before the
	// cache key is computed but most backend frameworks route to
	// /target regardless. Distinct from StrategySemicolonDelimiter
	// which only mutates with file extensions.
	StrategyCDNSessionSemicolon ProbeStrategy = "cdn-session-semicolon"
	// StrategyCDNQueryStrip produces /target?fbclid=...,
	// /target?__cf_chl_managed_tk__=..., /target?utm_source=....
	// CDNs strip these "tracking" parameters from the cache key but
	// the backend may render different content based on them. The
	// stripped parameter must not contain anything cache-busting.
	StrategyCDNQueryStrip ProbeStrategy = "cdn-query-strip"
)

// defaultStrategies returns every supported strategy. Used when DetectOptions
// has an empty Strategies list.
func defaultStrategies() []ProbeStrategy {
	return []ProbeStrategy{
		StrategyAppendExtension,
		StrategyPathSegment,
		StrategySemicolonDelimiter,
		StrategyEncodedNull,
		StrategyTrailingSlash,
		StrategyCDNSessionSemicolon,
		// StrategyCDNQueryStrip is intentionally off by default. It mutates
		// only the query string, leaving the path untouched, so any auth-
		// matching response is indistinguishable from a normal authenticated
		// fetch — the strategy needs a Cache-Control: public guardrail
		// before it can avoid false-positives. Opt in via DetectOptions.
		// Strategies when you've vetted the target's caching policy.
	}
}

// defaultExtensions are the cacheable file extensions caches will store
// regardless of Cache-Control directives in the upstream response. Curated
// from the default rule sets of Cloudflare, Fastly, Akamai, Varnish (built-
// in vcl_recv hint), and AWS CloudFront. Order matters only for evidence
// reporting; the detector tries them all up to MaxProbes.
func defaultExtensions() []string {
	return []string{
		".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
		".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot",
		".otf", ".webp", ".bmp", ".pdf", ".txt",
	}
}

// probeURL pairs a generated URL with the strategy label that produced it,
// so finding evidence can attribute the hit.
type probeURL struct {
	URL      string
	Strategy ProbeStrategy
}

// DetectionResult is the outcome of a single cache-deception probe.
type DetectionResult struct {
	Vulnerable     bool
	Findings       []*core.Finding
	TestedPayloads int
}

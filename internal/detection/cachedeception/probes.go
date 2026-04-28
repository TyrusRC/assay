package cachedeception

import (
	"net/url"
	"strings"
)

// generateProbeURLs produces deceptive URL variants of target according to
// the given strategies and extensions. The result is bounded by maxProbes;
// strategies are interleaved so a small cap still gets coverage from each
// family rather than 50 variants of one strategy.
//
// Returns nil if target cannot be parsed as a URL — the detector treats
// that as a non-error and emits zero findings, since attempting to scan a
// non-URL is an upstream caller bug.
func generateProbeURLs(target string, strategies []ProbeStrategy, extensions []string, maxProbes int) []probeURL {
	u, err := url.Parse(target)
	if err != nil {
		return nil
	}
	if u.Path == "" {
		u.Path = "/"
	}
	if maxProbes <= 0 {
		maxProbes = 50
	}
	if len(strategies) == 0 {
		strategies = defaultStrategies()
	}
	if len(extensions) == 0 {
		extensions = defaultExtensions()
	}

	// Build per-strategy lists, then interleave so a low MaxProbes still
	// samples every family.
	perStrategy := make([][]probeURL, 0, len(strategies))
	for _, s := range strategies {
		perStrategy = append(perStrategy, mutate(u, s, extensions))
	}

	out := make([]probeURL, 0, maxProbes)
	for round := 0; len(out) < maxProbes; round++ {
		added := false
		for _, list := range perStrategy {
			if round >= len(list) {
				continue
			}
			out = append(out, list[round])
			added = true
			if len(out) >= maxProbes {
				break
			}
		}
		if !added {
			break
		}
	}
	return out
}

// mutate produces every probe URL for one strategy/target pair.
func mutate(base *url.URL, strategy ProbeStrategy, extensions []string) []probeURL {
	switch strategy {
	case StrategyAppendExtension:
		return appendExtension(base, extensions)
	case StrategyPathSegment:
		return appendPathSegment(base, extensions)
	case StrategySemicolonDelimiter:
		return semicolonDelimiter(base, extensions)
	case StrategyEncodedNull:
		return encodedNull(base, extensions)
	case StrategyTrailingSlash:
		return trailingSlash(base, extensions)
	}
	return nil
}

// withPath returns a copy of base with its path replaced. We rebuild
// rather than mutate so the caller's URL isn't aliased.
func withPath(base *url.URL, path string) string {
	cp := *base
	cp.Path = path
	cp.RawPath = "" // let the encoder re-derive from Path
	return cp.String()
}

// withRawPath is like withPath but lets the caller pass percent-encoded
// path bytes directly. Used for strategies that need to preserve a literal
// %00 or %3B that net/url would otherwise re-encode.
func withRawPath(base *url.URL, rawPath string) string {
	cp := *base
	cp.Path = rawPath
	cp.RawPath = rawPath
	return cp.String()
}

func appendExtension(base *url.URL, exts []string) []probeURL {
	// /account → /account.css, /account.js, ...
	out := make([]probeURL, 0, len(exts))
	path := strings.TrimSuffix(base.Path, "/")
	for _, e := range exts {
		out = append(out, probeURL{
			URL:      withPath(base, path+e),
			Strategy: StrategyAppendExtension,
		})
	}
	return out
}

func appendPathSegment(base *url.URL, exts []string) []probeURL {
	// /account → /account/skws.css, /account/index.css
	out := make([]probeURL, 0, len(exts)*2)
	path := strings.TrimSuffix(base.Path, "/")
	for _, e := range exts {
		out = append(out,
			probeURL{URL: withPath(base, path+"/skws"+e), Strategy: StrategyPathSegment},
			probeURL{URL: withPath(base, path+"/index"+e), Strategy: StrategyPathSegment},
		)
	}
	return out
}

func semicolonDelimiter(base *url.URL, exts []string) []probeURL {
	// /account → /account;.css, /account;skws.css
	// We use withRawPath because url.URL would otherwise percent-encode the
	// semicolon when it appears in Path, defeating the bypass against
	// servers that strip path parameters before routing.
	out := make([]probeURL, 0, len(exts)*2)
	path := strings.TrimSuffix(base.Path, "/")
	for _, e := range exts {
		out = append(out,
			probeURL{URL: withRawPath(base, path+";"+e), Strategy: StrategySemicolonDelimiter},
			probeURL{URL: withRawPath(base, path+";skws"+e), Strategy: StrategySemicolonDelimiter},
		)
	}
	return out
}

func encodedNull(base *url.URL, exts []string) []probeURL {
	// /account → /account%00.css. Some servers truncate the path at NUL
	// before routing, but caches read the raw URL bytes as the key.
	out := make([]probeURL, 0, len(exts))
	path := strings.TrimSuffix(base.Path, "/")
	for _, e := range exts {
		out = append(out, probeURL{
			URL:      withRawPath(base, path+"%00"+e),
			Strategy: StrategyEncodedNull,
		})
	}
	return out
}

func trailingSlash(base *url.URL, exts []string) []probeURL {
	// /account → /account/, /account/.css
	out := make([]probeURL, 0, len(exts)+1)
	path := strings.TrimSuffix(base.Path, "/")
	out = append(out, probeURL{
		URL:      withPath(base, path+"/"),
		Strategy: StrategyTrailingSlash,
	})
	for _, e := range exts {
		out = append(out, probeURL{
			URL:      withPath(base, path+"/"+e),
			Strategy: StrategyTrailingSlash,
		})
	}
	return out
}

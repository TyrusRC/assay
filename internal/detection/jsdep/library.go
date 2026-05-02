// Package jsdep detects vulnerable JavaScript dependencies on a target by
// extracting library@version pairs from <script src=...> URLs and querying
// the NVD CVE API for matches against the corresponding CPE names.
package jsdep

import (
	"path"
	"regexp"
	"strings"
)

// Library identifies one detected JS library on the target page. CPEVendor
// and CPEProduct are the strings that appear in NVD's CPE 2.3 names —
// often, but not always, equal to the lowercased library name. ScriptURL
// is the absolute URL of the <script> that revealed it.
type Library struct {
	Name       string
	Version    string
	CPEVendor  string
	CPEProduct string
	ScriptURL  string
}

// libraryRule is one detection rule. Patterns capture the version (group
// 1) from a script-src URL.  CPE vendor/product map the library name to
// the strings NVD uses; missing them means we'd query an empty product
// and get empty results.
type libraryRule struct {
	Name       string
	CPEVendor  string
	CPEProduct string
	Patterns   []*regexp.Regexp
}

// libraryRules covers the JS libraries most commonly observed in real
// targets. Adding a new entry is one line; if the CPE vendor/product
// don't match the file name (common case) the explicit fields here are
// the source of truth.
var libraryRules = []libraryRule{
	{
		Name: "AngularJS", CPEVendor: "angularjs", CPEProduct: "angular.js",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)angular[._-](\d+[._-]\d+[._-]\d+)`),
			regexp.MustCompile(`(?i)angular(?:js)?[/-]v?(\d+\.\d+\.\d+)`),
		},
	},
	{
		Name: "jQuery", CPEVendor: "jquery", CPEProduct: "jquery",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js`),
			regexp.MustCompile(`(?i)jquery/(\d+\.\d+\.\d+)/`),
		},
	},
	{
		Name: "jQuery UI", CPEVendor: "jquery", CPEProduct: "jquery_ui",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)jquery[.-]ui[.-](\d+\.\d+\.\d+)(?:\.min)?\.js`),
		},
	},
	{
		Name: "Lodash", CPEVendor: "lodash", CPEProduct: "lodash",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)lodash[.-](\d+\.\d+\.\d+)(?:\.min)?\.js`),
		},
	},
	{
		Name: "Handlebars", CPEVendor: "handlebarsjs", CPEProduct: "handlebars",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)handlebars[.-]?v?(\d+\.\d+\.\d+)(?:\.min|\.runtime)?\.js`),
		},
	},
	{
		Name: "Bootstrap", CPEVendor: "getbootstrap", CPEProduct: "bootstrap",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)bootstrap[.-](\d+\.\d+\.\d+)(?:\.min|\.bundle)?\.js`),
		},
	},
	{
		Name: "Moment.js", CPEVendor: "momentjs", CPEProduct: "moment",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)moment[.-](\d+\.\d+\.\d+)(?:\.min)?\.js`),
		},
	},
	{
		Name: "DOMPurify", CPEVendor: "dompurify_project", CPEProduct: "dompurify",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(?:dompurify|purify)[.-](\d+\.\d+\.\d+)(?:\.min)?\.js`),
		},
	},
	{
		Name: "React", CPEVendor: "facebook", CPEProduct: "react",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)react[.-](\d+\.\d+\.\d+)(?:\.development|\.production|\.min)?\.js`),
		},
	},
	{
		Name: "Vue.js", CPEVendor: "vuejs", CPEProduct: "vue.js",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)vue[.-](\d+\.\d+\.\d+)(?:\.min)?\.js`),
		},
	},
	{
		Name: "Axios", CPEVendor: "axios", CPEProduct: "axios",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)axios[.-](\d+\.\d+\.\d+)(?:\.min)?\.js`),
		},
	},
}

// IdentifyLibrary inspects a single script-src URL and returns the
// detected Library, or nil if no rule matched. We match against the
// filename (last URL segment) rather than the whole URL — CDN paths often
// contain "1.7.7" in the directory portion that would FP-match weaker
// patterns.
func IdentifyLibrary(scriptURL string) *Library {
	if scriptURL == "" {
		return nil
	}
	// Strip query/fragment so they don't pollute regex captures.
	if i := strings.IndexAny(scriptURL, "?#"); i >= 0 {
		scriptURL = scriptURL[:i]
	}
	filename := path.Base(scriptURL)

	for _, rule := range libraryRules {
		for _, p := range rule.Patterns {
			// Try filename first (cheap, specific).
			if m := p.FindStringSubmatch(filename); len(m) >= 2 {
				return &Library{
					Name:       rule.Name,
					Version:    normalizeVersion(m[1]),
					CPEVendor:  rule.CPEVendor,
					CPEProduct: rule.CPEProduct,
					ScriptURL:  scriptURL,
				}
			}
			// Fall back to the full URL for path-style versioning.
			if m := p.FindStringSubmatch(scriptURL); len(m) >= 2 {
				return &Library{
					Name:       rule.Name,
					Version:    normalizeVersion(m[1]),
					CPEVendor:  rule.CPEVendor,
					CPEProduct: rule.CPEProduct,
					ScriptURL:  scriptURL,
				}
			}
		}
	}
	return nil
}

// normalizeVersion converts filename separators ('-' / '_') to dots,
// matching CPE 2.3 version syntax. PortSwigger's lab serves
// `angular_1-7-7.js`, which we want to query NVD as version "1.7.7".
func normalizeVersion(v string) string {
	v = strings.ReplaceAll(v, "_", ".")
	v = strings.ReplaceAll(v, "-", ".")
	return v
}

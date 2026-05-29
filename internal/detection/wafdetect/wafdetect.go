// Package wafdetect identifies Web Application Firewalls from
// response signatures (headers, cookies, body markers, status codes).
//
// The detector is passive: it inspects an existing HTTP response rather
// than crafting probes. That keeps it cheap to run on every request the
// scanner already issues and avoids the noise of an active wafw00f-style
// canary scan. Downstream payload selection (XSS / SQLi / SSRF) reads
// the detected vendor to switch in evasion-class payloads.
//
// Mirrors AWVS WAF_Detection.script in scope. Fingerprint sources:
// wafw00f signature DB, Cloudflare/Akamai/AWS WAF/Imperva/F5/Sucuri
// public docs, the OWASP CRS body markers for ModSecurity.
package wafdetect

import (
	"bytes"
	"net/http"
	"regexp"
	"strings"
)

// HeaderTell matches a response header by name (case-insensitive) with an
// optional substring check on the value. Empty ValueContains matches any
// non-empty value for that header.
type HeaderTell struct {
	Name          string
	ValueContains string
}

// CookieTell matches a Set-Cookie name prefix (case-insensitive).
type CookieTell struct {
	NamePrefix string
}

// BodyTell matches a substring or regex against the response body.
type BodyTell struct {
	Contains string         // case-insensitive substring; empty means use Regex
	Regex    *regexp.Regexp // optional; takes precedence over Contains when set
}

// Fingerprint identifies one WAF vendor by any of its tells.
type Fingerprint struct {
	Vendor        string
	HeaderTells   []HeaderTell
	CookieTells   []CookieTell
	BodyTells     []BodyTell
	BlockStatus   []int // status codes the WAF returns when blocking (informational)
}

// Match is the result of a positive fingerprint hit.
type Match struct {
	Vendor     string
	Confidence int    // 1-100; 90+ for header-level matches, 70 for cookie, 60 for body-only
	Evidence   string // short human-readable trace ("header Cf-Ray=abc123")
}

// Detect runs every fingerprint against the response and returns matches.
// Returns nil for a nil response.
func Detect(resp *http.Response, body []byte) []Match {
	if resp == nil {
		return nil
	}
	var matches []Match
	seen := make(map[string]bool, len(fingerprints))
	for _, fp := range fingerprints {
		if seen[fp.Vendor] {
			continue
		}
		if m, ok := evaluate(fp, resp, body); ok {
			matches = append(matches, m)
			seen[fp.Vendor] = true
		}
	}
	return matches
}

// Fingerprints returns the static fingerprint table.
func Fingerprints() []Fingerprint {
	return fingerprints
}

func evaluate(fp Fingerprint, resp *http.Response, body []byte) (Match, bool) {
	for _, ht := range fp.HeaderTells {
		v := resp.Header.Get(ht.Name)
		if v == "" {
			continue
		}
		if ht.ValueContains != "" && !strings.Contains(strings.ToLower(v), strings.ToLower(ht.ValueContains)) {
			continue
		}
		return Match{
			Vendor:     fp.Vendor,
			Confidence: 95,
			Evidence:   "header " + ht.Name + "=" + truncate(v, 60),
		}, true
	}
	for _, ct := range fp.CookieTells {
		for _, raw := range resp.Header.Values("Set-Cookie") {
			name := cookieName(raw)
			if strings.HasPrefix(strings.ToLower(name), strings.ToLower(ct.NamePrefix)) {
				return Match{
					Vendor:     fp.Vendor,
					Confidence: 75,
					Evidence:   "cookie " + name,
				}, true
			}
		}
	}
	if len(body) > 0 {
		lc := bytes.ToLower(body)
		for _, bt := range fp.BodyTells {
			if bt.Regex != nil {
				if bt.Regex.Match(body) {
					return Match{
						Vendor:     fp.Vendor,
						Confidence: 65,
						Evidence:   "body regex " + bt.Regex.String(),
					}, true
				}
				continue
			}
			if bt.Contains != "" && bytes.Contains(lc, []byte(strings.ToLower(bt.Contains))) {
				return Match{
					Vendor:     fp.Vendor,
					Confidence: 65,
					Evidence:   "body contains " + bt.Contains,
				}, true
			}
		}
	}
	return Match{}, false
}

func cookieName(raw string) string {
	if i := strings.Index(raw, "="); i >= 0 {
		return strings.TrimSpace(raw[:i])
	}
	return strings.TrimSpace(raw)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// fingerprints — the static signature DB. Order is informational only;
// Detect dedupes by Vendor.
var fingerprints = []Fingerprint{
	{
		Vendor: "Cloudflare",
		HeaderTells: []HeaderTell{
			{Name: "Server", ValueContains: "cloudflare"},
			{Name: "Cf-Ray"},
			{Name: "Cf-Cache-Status"},
			{Name: "Cf-Request-Id"},
		},
		CookieTells: []CookieTell{{NamePrefix: "__cfduid"}, {NamePrefix: "__cf_bm"}, {NamePrefix: "cf_clearance"}},
		BlockStatus: []int{403, 503, 520, 521, 522, 524},
	},
	{
		Vendor: "Akamai",
		HeaderTells: []HeaderTell{
			{Name: "Server", ValueContains: "AkamaiGHost"},
			{Name: "X-Akamai-Transformed"},
			{Name: "X-Akamai-Request-Id"},
		},
		CookieTells: []CookieTell{{NamePrefix: "ak_bmsc"}, {NamePrefix: "akacd_"}, {NamePrefix: "AKA_A2"}},
		BodyTells:   []BodyTell{{Contains: "Reference&#32;&#35;"}, {Contains: "akamai reference"}},
	},
	{
		Vendor: "AWS WAF",
		HeaderTells: []HeaderTell{
			{Name: "X-Amzn-Errortype", ValueContains: "WAF"},
			{Name: "X-Amz-Cf-Id"},
		},
		CookieTells: []CookieTell{{NamePrefix: "aws-waf-token"}},
		BodyTells:   []BodyTell{{Contains: "AWS WAF"}, {Contains: "Request blocked"}},
	},
	{
		Vendor: "Imperva",
		HeaderTells: []HeaderTell{
			{Name: "X-Iinfo"},
			{Name: "X-CDN", ValueContains: "Imperva"},
		},
		CookieTells: []CookieTell{{NamePrefix: "visid_incap_"}, {NamePrefix: "incap_ses_"}, {NamePrefix: "nlbi_"}},
		BodyTells:   []BodyTell{{Contains: "Incapsula incident"}, {Contains: "_Incapsula_Resource"}},
	},
	{
		Vendor: "F5 BIG-IP ASM",
		HeaderTells: []HeaderTell{
			{Name: "X-WA-Info"},
			{Name: "X-Cnection", ValueContains: "close"},
		},
		CookieTells: []CookieTell{{NamePrefix: "TS"}, {NamePrefix: "BIGipServer"}, {NamePrefix: "F5_ST"}, {NamePrefix: "LastMRH_Session"}},
		BodyTells:   []BodyTell{{Contains: "The requested URL was rejected"}, {Contains: "Support ID"}},
		BlockStatus: []int{403, 419, 503},
	},
	{
		Vendor: "ModSecurity",
		HeaderTells: []HeaderTell{
			{Name: "Server", ValueContains: "Mod_Security"},
			{Name: "Server", ValueContains: "NOYB"},
		},
		BodyTells: []BodyTell{
			{Contains: "Mod_Security"},
			{Contains: "ModSecurity"},
			{Contains: "Reference #18"},
			{Contains: "This error was generated by Mod_Security"},
		},
		BlockStatus: []int{403, 406, 501},
	},
	{
		Vendor: "Sucuri",
		HeaderTells: []HeaderTell{
			{Name: "Server", ValueContains: "Sucuri/Cloudproxy"},
			{Name: "X-Sucuri-ID"},
			{Name: "X-Sucuri-Cache"},
		},
		BodyTells: []BodyTell{{Contains: "Access Denied - Sucuri Website Firewall"}, {Contains: "sucuri cloudproxy"}},
	},
	{
		Vendor: "Wallarm",
		HeaderTells: []HeaderTell{
			{Name: "X-Wallarm-Mode"},
			{Name: "Nginx-Wallarm-Mode"},
		},
		BodyTells: []BodyTell{{Contains: "wallarm.com"}},
	},
	{
		Vendor: "FortiWeb",
		HeaderTells: []HeaderTell{{Name: "Server", ValueContains: "FortiWeb"}},
		CookieTells: []CookieTell{{NamePrefix: "cookiesession"}, {NamePrefix: "FORTIWAFSID"}},
		BodyTells:   []BodyTell{{Contains: "Server unavailable"}, {Contains: "FortiWeb"}},
	},
	{
		Vendor: "Barracuda",
		HeaderTells: []HeaderTell{{Name: "Server", ValueContains: "Barracuda"}},
		CookieTells: []CookieTell{{NamePrefix: "barra_counter_session"}, {NamePrefix: "BNI_persistence"}, {NamePrefix: "BNI__BARRACUDA_LB_COOKIE"}},
	},
	{
		Vendor: "Citrix NetScaler",
		HeaderTells: []HeaderTell{
			{Name: "Via", ValueContains: "NS-CACHE"},
			{Name: "Cneonction"},
			{Name: "nnCoection"},
		},
		CookieTells: []CookieTell{{NamePrefix: "citrix_ns_id"}, {NamePrefix: "NSC_"}},
	},
	{
		Vendor: "Azure Front Door",
		HeaderTells: []HeaderTell{
			{Name: "X-Azure-Ref"},
			{Name: "X-Cache", ValueContains: "FRONTDOOR"},
		},
		BodyTells: []BodyTell{{Contains: "Microsoft-Azure-Application-Gateway/"}},
	},
	{
		Vendor: "Cloudfront",
		HeaderTells: []HeaderTell{
			{Name: "Via", ValueContains: "cloudfront"},
			{Name: "X-Amz-Cf-Pop"},
		},
	},
	{
		Vendor: "DenyAll",
		HeaderTells: []HeaderTell{{Name: "X-Denyall-User"}},
		CookieTells: []CookieTell{{NamePrefix: "sessioncookie"}},
	},
	{
		Vendor: "Reblaze",
		HeaderTells: []HeaderTell{{Name: "Server", ValueContains: "Reblaze Secure Web Gateway"}},
		CookieTells: []CookieTell{{NamePrefix: "rbzid"}, {NamePrefix: "rbzsessionid"}},
	},
	{
		Vendor: "ArvanCloud",
		HeaderTells: []HeaderTell{
			{Name: "Server", ValueContains: "ArvanCloud"},
			{Name: "Ar-Real-Ip"},
		},
	},
}

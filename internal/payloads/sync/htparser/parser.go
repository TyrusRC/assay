package htparser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/TyrusRC/assay/internal/payloads/sync/patparser"
)

// classKeywords maps a canonical attack-class slug to the path
// substrings that, when present in a HackTricks page's relative path,
// classify that page under the slug. HackTricks lacks PayloadAllTheThings'
// clean top-level folders, so we lean on URL-slug conventions instead.
//
// First match wins. Entries are deliberately ordered most-specific
// first ("sql-injection" before "injection") to avoid mis-routing.
var classKeywords = []classRule{
	// Web injection families
	{Class: "sqli", Patterns: []string{"sql-injection", "sqli"}},
	{Class: "xss", Patterns: []string{"xss-cross-site-scripting", "xss", "cross-site-scripting"}},
	{Class: "ssti", Patterns: []string{"ssti-server-side-template-injection", "server-side-template-injection", "ssti"}},
	{Class: "ssrf", Patterns: []string{"ssrf-server-side-request-forgery", "server-side-request-forgery", "ssrf"}},
	{Class: "xxe", Patterns: []string{"xxe-xee-xml-external-entity", "xml-external-entity", "xxe"}},
	{Class: "nosql", Patterns: []string{"nosql-injection", "nosql"}},
	{Class: "ldap", Patterns: []string{"ldap-injection"}},
	{Class: "xpath", Patterns: []string{"xpath-injection", "xpath"}},
	{Class: "ssi", Patterns: []string{"server-side-inclusion", "server-side-include"}},
	{Class: "lfi", Patterns: []string{"file-inclusion", "lfi", "rfi", "path-traversal"}},
	{Class: "cmdi", Patterns: []string{"command-injection"}},
	{Class: "jndi", Patterns: []string{"jndi", "log4shell"}},

	// Session / auth / token
	{Class: "csrf", Patterns: []string{"csrf-cross-site-request-forgery", "csrf"}},
	{Class: "crlf", Patterns: []string{"crlf-0d-0a", "crlf"}},
	{Class: "jwt", Patterns: []string{"jwt-vulnerabilities", "jwt", "json-web-token"}},
	{Class: "oauth", Patterns: []string{"oauth"}},
	{Class: "saml", Patterns: []string{"saml-attacks", "saml"}},

	// Redirect / clickjack / open-things
	{Class: "redirect", Patterns: []string{"open-redirect", "url-redirection"}},
	{Class: "tabnabbing", Patterns: []string{"reverse-tab-nabbing"}},

	// Cache / smuggling / proxy
	{Class: "cachedeception", Patterns: []string{"cache-deception"}},
	{Class: "cachepoisoning", Patterns: []string{"cache-poisoning"}},
	{Class: "smuggling", Patterns: []string{"http-request-smuggling", "smuggling"}},
	{Class: "hosthdr", Patterns: []string{"abusing-hop-by-hop-headers", "host-header"}},

	// CORS / CSP / headers
	{Class: "cors", Patterns: []string{"cors-bypass", "cors"}},
	{Class: "secheaders", Patterns: []string{"content-security-policy-csp-bypass", "csp-bypass"}},

	// Deser / proto / mass-assign
	{Class: "deser", Patterns: []string{"deserialization"}},
	{Class: "protopollution", Patterns: []string{"prototype-pollution"}},
	{Class: "massassign", Patterns: []string{"mass-assignment", "parameter-pollution"}},
	{Class: "hpp", Patterns: []string{"parameter-pollution", "hpp"}},

	// File upload / web sockets / clickjack
	{Class: "fileupload", Patterns: []string{"file-upload"}},
	{Class: "ws", Patterns: []string{"websocket"}},
	{Class: "clickjacking", Patterns: []string{"clickjacking"}},

	// API / GraphQL
	{Class: "graphql", Patterns: []string{"graphql"}},

	// Race / DoS / regex
	{Class: "racecond", Patterns: []string{"race-condition"}},
	{Class: "redos", Patterns: []string{"regular-expression-denial-of-service", "redos"}},

	// DOM-side
	{Class: "domclobber", Patterns: []string{"dom-clobbering"}},
	{Class: "postmsg", Patterns: []string{"postmessage", "post-message"}},

	// Misc
	{Class: "cssinj", Patterns: []string{"css-injection"}},
	{Class: "csvinj", Patterns: []string{"csv-injection", "formula-injection"}},
	{Class: "emailinj", Patterns: []string{"email-injections"}},
	{Class: "htmlinj", Patterns: []string{"html-injection"}},
	{Class: "csti", Patterns: []string{"client-side-template-injection"}},
	{Class: "rfi", Patterns: []string{"remote-file-inclusion"}},
}

type classRule struct {
	Class    string
	Patterns []string
}

// noisyDirs are tree-walk skip prefixes that show up in HackTricks
// book builds and vendored deps but never carry usable payloads.
var noisyDirs = map[string]bool{
	"node_modules": true,
	".git":         true,
	"_book":        true,
	"site":         true, // mkdocs build output
	"book":         true,
}

// ClassForPath returns the canonical class slug for a HackTricks page
// path. Returns "" when no rule matches; callers should skip such
// pages rather than emit unclassified payloads.
//
// Matching is token-bounded: "sql-injection" matches "/sql-injection/"
// but NOT "/nosql-injection/" — substring matching would route the
// latter to sqli instead of nosql.
func ClassForPath(relPath string) string {
	lower := strings.ToLower(filepath.ToSlash(relPath))
	for _, rule := range classKeywords {
		for _, pat := range rule.Patterns {
			if containsToken(lower, pat) {
				return rule.Class
			}
		}
	}
	return ""
}

// containsToken reports whether s contains token surrounded by
// path-slug boundaries (/, -, ., _, or string edges). Used to avoid
// "sqli" inside "nosqli" matching the sqli rule.
func containsToken(s, token string) bool {
	for idx := 0; ; {
		i := strings.Index(s[idx:], token)
		if i < 0 {
			return false
		}
		start := idx + i
		end := start + len(token)
		beforeOK := start == 0 || isPathBoundary(s[start-1])
		afterOK := end == len(s) || isPathBoundary(s[end])
		if beforeOK && afterOK {
			return true
		}
		idx = start + 1
	}
}

func isPathBoundary(c byte) bool {
	switch c {
	case '/', '-', '.', '_':
		return true
	}
	return false
}

// ParseDir walks a HackTricks markdown source tree and emits a Catalog
// of classified payloads. Files whose relative path doesn't match any
// classKeywords rule are skipped — better to drop a page than to dump
// random payloads under the wrong attack class.
func ParseDir(rootDir string) (*patparser.Catalog, error) {
	info, err := os.Stat(rootDir)
	if err != nil {
		return nil, fmt.Errorf("htparser: stat %s: %w", rootDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("htparser: %s is not a directory", rootDir)
	}

	cat := &patparser.Catalog{
		Payloads: make([]patparser.Payload, 0, 256),
		Sources:  []string{rootDir},
	}

	walkErr := filepath.Walk(rootDir, func(p string, fi os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		if fi.IsDir() {
			if noisyDirs[fi.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.EqualFold(filepath.Ext(p), ".md") {
			return nil
		}
		rel, _ := filepath.Rel(rootDir, p)
		class := ClassForPath(rel)
		if class == "" {
			return nil
		}
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		subtype := strings.TrimSuffix(filepath.Base(p), filepath.Ext(p))
		payloads := patparser.ExtractMarkdownBlocks(string(data), class, subtype, p)
		cat.Payloads = append(cat.Payloads, payloads...)
		return nil
	})
	if walkErr != nil {
		return cat, walkErr
	}
	return cat, nil
}

// Package cspt detects Client-Side Path Traversal (CSPT) sinks in
// browser-side JavaScript. CSPT arises when a page concatenates an
// attacker-influenced value (a query parameter, URL fragment, or client-router
// param) into the *path* of a same-origin fetch/XHR request. An attacker can
// then inject ../ to redirect the authenticated request to a different
// endpoint — the primitive behind recent cache-deception account-takeover
// chains.
//
// The analyzer is a conservative source→sink heuristic over JS source text. It
// flags a sink only when a tainted value is concatenated into the path portion
// of a request URL (before any query string), which is the precondition for
// traversal. Taint that lands in a query string, or a fully attacker-supplied
// URL (an SSRF/open-redirect concern, not CSPT), is deliberately ignored.
package cspt

import (
	"regexp"
	"strings"
)

// Sink is a detected CSPT sink: a request call whose path embeds tainted input.
type Sink struct {
	// Call is the sink function, e.g. "fetch", "axios.get", "XMLHttpRequest.open".
	Call string
	// Source is the taint source that reaches the sink, best-effort.
	Source string
	// Snippet is the offending call text.
	Snippet string
}

// taintSources are substrings (matched case-insensitively) that introduce
// attacker-influenced data on the client side.
var taintSources = []string{
	"location.search", "location.hash", "location.href", "location.pathname",
	"document.url", "document.documenturi", "document.baseuri", "window.name",
	"useparams(", ".searchparams.get(", "urlsearchparams(",
	"$route.params", "route.params",
}

var assignRe = regexp.MustCompile(`(?:^|[;{}\n])\s*(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*([^;\n]*)`)

// sinkRe finds request-issuing calls. The captured group names the call.
var sinkRe = regexp.MustCompile(`(fetch|axios\.(?:get|post|put|delete|patch)|axios|XMLHttpRequest|\.open|\$\.(?:ajax|get|post)|\.ajax)\s*\(`)

// Analyze scans JavaScript source and returns the CSPT sinks it finds.
func Analyze(js string) []Sink {
	tainted := collectTaintedVars(js)
	calls := findSinkCalls(js)
	sinks := make([]Sink, 0, len(calls))
	for _, call := range calls {
		arg := call.urlArg()
		if arg == "" {
			continue
		}
		src, ok := urlArgIsCSPT(arg, tainted)
		if !ok {
			continue
		}
		sinks = append(sinks, Sink{Call: call.name, Source: src, Snippet: strings.TrimSpace(call.text)})
	}
	return sinks
}

// collectTaintedVars returns the set of variable names assigned, directly or
// transitively, from a taint source. It iterates to a fixed point so that
// `a = location.search; b = a.split('/')` taints both a and b.
func collectTaintedVars(js string) map[string]bool {
	tainted := make(map[string]bool)
	for {
		changed := false
		for _, m := range assignRe.FindAllStringSubmatch(js, -1) {
			name, rhs := m[1], m[2]
			if tainted[name] {
				continue
			}
			if exprReferencesTaint(rhs, tainted) {
				tainted[name] = true
				changed = true
			}
		}
		if !changed {
			return tainted
		}
	}
}

// exprReferencesTaint reports whether an expression reads a taint source or a
// known tainted variable.
func exprReferencesTaint(expr string, tainted map[string]bool) bool {
	low := strings.ToLower(expr)
	for _, s := range taintSources {
		if strings.Contains(low, s) {
			return true
		}
	}
	for name := range tainted {
		if containsIdent(expr, name) {
			return true
		}
	}
	return false
}

// containsIdent reports whether expr contains name as a standalone identifier
// (not as part of a longer word).
func containsIdent(expr, name string) bool {
	re := regexp.MustCompile(`(^|[^\w$])` + regexp.QuoteMeta(name) + `($|[^\w$])`)
	return re.MatchString(expr)
}

// urlArgIsCSPT reports whether a sink's URL argument embeds tainted input in
// the path. It returns the matched source description.
func urlArgIsCSPT(arg string, tainted map[string]bool) (string, bool) {
	arg = strings.TrimSpace(arg)
	if strings.HasPrefix(arg, "`") {
		return templateIsCSPT(arg, tainted)
	}
	return concatIsCSPT(arg, tainted)
}

// templateIsCSPT handles template-literal URLs: `/api/data/${p}/info`.
func templateIsCSPT(arg string, tainted map[string]bool) (string, bool) {
	inner := strings.Trim(arg, "`")
	holes := regexp.MustCompile(`\$\{([^}]*)\}`).FindAllStringSubmatchIndex(inner, -1)
	for _, h := range holes {
		expr := inner[h[2]:h[3]]
		if !exprReferencesTaint(expr, tainted) {
			continue
		}
		prefix := inner[:h[0]]
		if isPathPrefix(prefix) {
			return strings.TrimSpace(expr), true
		}
	}
	return "", false
}

// concatIsCSPT handles string-concatenation URLs: '/api/users/' + id.
func concatIsCSPT(arg string, tainted map[string]bool) (string, bool) {
	parts := splitTopLevelPlus(arg)
	var urlText strings.Builder
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if lit, ok := stringLiteral(p); ok {
			urlText.WriteString(lit)
			continue
		}
		if exprReferencesTaint(p, tainted) {
			if isPathPrefix(urlText.String()) {
				return p, true
			}
			return "", false
		}
		// Unknown non-literal token: we can't track its contribution to the
		// URL text, so stop accumulating a reliable prefix.
		urlText.WriteString("\x00")
	}
	return "", false
}

// isPathPrefix reports whether the URL text accumulated before a tainted
// insertion is a path (contains '/') that has not yet reached a query string.
func isPathPrefix(prefix string) bool {
	if strings.Contains(prefix, "?") {
		return false
	}
	return strings.Contains(prefix, "/")
}

// stringLiteral returns the unquoted contents of a single/double-quoted string
// literal token, and whether the token was such a literal.
func stringLiteral(tok string) (string, bool) {
	if len(tok) < 2 {
		return "", false
	}
	q := tok[0]
	if (q == '\'' || q == '"') && tok[len(tok)-1] == q {
		return tok[1 : len(tok)-1], true
	}
	return "", false
}

// splitTopLevelPlus splits a concatenation expression on '+' operators that sit
// outside of quotes, brackets, and parentheses.
func splitTopLevelPlus(expr string) []string {
	var parts []string
	var cur strings.Builder
	depth := 0
	var quote byte
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"' || c == '`':
			quote = c
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		case c == '+' && depth == 0:
			parts = append(parts, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	parts = append(parts, cur.String())
	return parts
}

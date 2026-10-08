// Package scope decides whether a URL may be requested during a scan. The HTTP
// client consults a Scope before every outbound request, so a scan never wanders
// outside the operator's declared targets. A nil *Scope allows everything —
// callers opt in to restriction.
package scope

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Scope is an allow/deny policy over request URLs: a host allowlist plus optional
// path include and exclude rules. Exclude always wins. When the host list is
// empty, any host is allowed (path rules still apply). When the include list is
// non-empty, a path must match at least one include to be in scope.
type Scope struct {
	hosts   []hostPattern
	include []*regexp.Regexp
	exclude []*regexp.Regexp
}

type hostPattern struct {
	wildcard bool   // true for "*.example.com"
	value    string // ".example.com" when wildcard, else the exact host
}

// DefaultExcludes are paths a scan must never request — they end the session or
// destroy state. They apply unless the operator opts out.
var DefaultExcludes = []string{
	`(?i)/logout\b`,
	`(?i)/sign[_-]?out\b`,
	`(?i)/log[_-]?off\b`,
	`(?i)/delete[_-]?account\b`,
	`(?i)/account/delete\b`,
}

// New builds a Scope. hosts are wildcard ("*.example.com") or exact host
// patterns; an empty list allows any host. include and exclude are regular
// expressions matched against the request path with its query string. When
// withDefaultExcludes is true, DefaultExcludes are prepended to exclude. An
// invalid regular expression returns an error.
func New(hosts, include, exclude []string, withDefaultExcludes bool) (*Scope, error) {
	s := &Scope{}
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if strings.HasPrefix(h, "*.") {
			s.hosts = append(s.hosts, hostPattern{wildcard: true, value: h[1:]})
		} else {
			s.hosts = append(s.hosts, hostPattern{value: h})
		}
	}

	compile := func(pats []string) ([]*regexp.Regexp, error) {
		var out []*regexp.Regexp
		for _, p := range pats {
			if strings.TrimSpace(p) == "" {
				continue
			}
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("invalid scope pattern %q: %w", p, err)
			}
			out = append(out, re)
		}
		return out, nil
	}

	var err error
	if s.include, err = compile(include); err != nil {
		return nil, err
	}
	exc := exclude
	if withDefaultExcludes {
		exc = append(append([]string{}, DefaultExcludes...), exclude...)
	}
	if s.exclude, err = compile(exc); err != nil {
		return nil, err
	}
	return s, nil
}

// InScope reports whether rawURL may be requested. A nil Scope allows everything.
// A URL that does not parse is out of scope (fail closed).
func (s *Scope) InScope(rawURL string) bool {
	if s == nil {
		return true
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if len(s.hosts) > 0 && !s.hostAllowed(host) {
		return false
	}

	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	pq := path
	if u.RawQuery != "" {
		pq = path + "?" + u.RawQuery
	}

	for _, re := range s.exclude {
		if re.MatchString(pq) {
			return false
		}
	}
	if len(s.include) > 0 {
		for _, re := range s.include {
			if re.MatchString(pq) {
				return true
			}
		}
		return false
	}
	return true
}

func (s *Scope) hostAllowed(host string) bool {
	for _, h := range s.hosts {
		if h.wildcard {
			// "*.example.com" matches sub.example.com and example.com itself.
			if strings.HasSuffix(host, h.value) || host == strings.TrimPrefix(h.value, ".") {
				return true
			}
		} else if host == h.value {
			return true
		}
	}
	return false
}

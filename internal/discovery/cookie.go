package discovery

import (
	"context"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// CookieDiscoverer extracts injectable parameters from Set-Cookie response headers.
type CookieDiscoverer struct{}

// NewCookieDiscoverer creates a new CookieDiscoverer.
func NewCookieDiscoverer() *CookieDiscoverer {
	return &CookieDiscoverer{}
}

// Name returns the discoverer identifier.
func (c *CookieDiscoverer) Name() string {
	return "cookie"
}

// Discover extracts cookie parameters from Set-Cookie headers.
// The internal HTTP client joins multiple Set-Cookie headers into a single
// comma-separated value, so we handle both formats.
func (c *CookieDiscoverer) Discover(_ context.Context, _ string, resp *http.Response) ([]core.Parameter, error) {
	if resp == nil {
		return nil, nil
	}

	var params []core.Parameter
	seen := make(map[string]bool)

	// Check for Set-Cookie header (may be joined with commas)
	setCookie := resp.Headers["Set-Cookie"]
	if setCookie == "" {
		// Try lowercase
		setCookie = resp.Headers["set-cookie"]
	}
	if setCookie == "" {
		return nil, nil
	}

	// Split on commas that separate multiple Set-Cookie values.
	// Each cookie: "name=value; attr1; attr2"
	cookies := splitSetCookies(setCookie)

	for _, cookie := range cookies {
		cookie = strings.TrimSpace(cookie)
		if cookie == "" {
			continue
		}

		// Extract name=value (before first semicolon)
		parts := strings.SplitN(cookie, ";", 2)
		nameValue := strings.TrimSpace(parts[0])

		eqIdx := strings.IndexByte(nameValue, '=')
		if eqIdx < 1 {
			continue
		}

		name := strings.TrimSpace(nameValue[:eqIdx])
		value := strings.TrimSpace(nameValue[eqIdx+1:])

		if !seen[name] {
			seen[name] = true
			params = append(params, core.Parameter{
				Name:     name,
				Location: core.ParamLocationCookie,
				Value:    value,
				Type:     "string",
			})
		}
	}

	return params, nil
}

// splitSetCookies splits a joined Set-Cookie header into individual cookies.
// Cookies are separated by commas, but commas can appear in Expires dates.
// We handle this by looking for "name=" patterns after commas.
func splitSetCookies(header string) []string {
	var cookies []string
	current := ""

	parts := strings.Split(header, ",")
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		// If the part contains '=' and the part before '=' doesn't contain ';',
		// it's likely a new cookie. Otherwise it's a continuation (e.g., Expires date).
		if current != "" && looksLikeNewCookie(trimmed) {
			cookies = append(cookies, current)
			current = trimmed
		} else if current == "" {
			current = trimmed
		} else {
			current += "," + part
		}
	}
	if current != "" {
		cookies = append(cookies, current)
	}

	return cookies
}

// looksLikeNewCookie checks if a string looks like the start of a new cookie (name=value).
func looksLikeNewCookie(s string) bool {
	// A new cookie starts with a token (name) followed by '='
	// before any ';' character
	eqIdx := strings.IndexByte(s, '=')
	semiIdx := strings.IndexByte(s, ';')
	if eqIdx < 1 {
		return false
	}
	if semiIdx >= 0 && semiIdx < eqIdx {
		return false
	}
	// Check the name part is a valid token (no spaces before =)
	name := s[:eqIdx]
	return !strings.ContainsAny(name, " \t")
}

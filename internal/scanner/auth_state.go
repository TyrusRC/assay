package scanner

import (
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// AuthState captures a single identity's auth material for the
// two-identity IDOR / BOLA probe. Either field may be empty;
// HasAuth reports whether at least one carries data.
type AuthState struct {
	// Cookies is a raw Cookie header value, e.g. "session=abc; csrf=xyz".
	Cookies string
	// Headers maps header name → value. Use this for Authorization,
	// X-Auth-Token, etc. Header values are sent verbatim.
	Headers map[string]string
}

// HasAuth reports whether the AuthState carries any auth material.
// Empty AuthStates are treated as "not provided" by the orchestrator.
func (a AuthState) HasAuth() bool {
	if strings.TrimSpace(a.Cookies) != "" {
		return true
	}
	for k, v := range a.Headers {
		if strings.TrimSpace(k) != "" && strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

// buildAuthClient renders an *http.Client carrying the given auth state
// while inheriting the base client's transport configuration (proxy,
// insecure, timeout, user-agent). Used to spin up the victim/attacker
// clients for cross-identity probing without mutating the shared client.
func buildAuthClient(base *http.Client, auth AuthState) *http.Client {
	c := http.NewClient()
	if base != nil {
		snap := base.Snapshot()
		if snap.UserAgent != "" {
			c.WithUserAgent(snap.UserAgent)
		}
		if snap.ProxyURL != "" {
			c.WithProxy(snap.ProxyURL)
		}
		if snap.Insecure {
			c.WithInsecure(true)
		}
	}
	if auth.Cookies != "" {
		c.WithCookies(auth.Cookies)
	}
	if len(auth.Headers) > 0 {
		clean := make(map[string]string, len(auth.Headers))
		for k, v := range auth.Headers {
			if strings.TrimSpace(k) == "" {
				continue
			}
			clean[k] = v
		}
		if len(clean) > 0 {
			c.WithHeaders(clean)
		}
	}
	return c
}

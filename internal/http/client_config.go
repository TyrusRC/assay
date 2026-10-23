// client_config.go — builder methods (With*), Clone, ForParam, Snapshot,
// and client lifecycle (rebuildNeeded, ensureClient) for the HTTP client.
package http

import (
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/scope"
)

// Clone creates an independent copy of the client with the same config.
func (c *Client) Clone() *Client {
	cloned := &Client{
		headers:         make(map[string]string, len(c.headers)),
		cookies:         c.cookies,
		proxyURL:        c.proxyURL,
		timeout:         c.timeout,
		followRedirects: c.followRedirects,
		userAgent:       c.userAgent,
		insecure:        c.insecure,
		scope:           c.scope,
		throttle:        c.throttle,
		cookieSrc:       c.cookieSrc,
		paramOverride:   c.paramOverride,
		siblingParams:   c.siblingParams,
	}
	for k, v := range c.headers {
		cloned.headers[k] = v
	}
	cloned.buildHTTPClient()
	return cloned
}

// WithCookieSource attaches a live cookie provider. When set and it returns a
// non-empty string, Do uses it for the Cookie header in place of the static
// cookie — so a session re-authenticated mid-scan is picked up by every client
// that shares the source, with no rebuild. Shared by pointer through Clone.
func (c *Client) WithCookieSource(fn func() string) *Client {
	c.cookieSrc = fn
	return c
}

// WithScope attaches a scope policy. Do blocks any request whose URL the scope
// rejects. A nil scope allows every request (the default).
func (c *Client) WithScope(s *scope.Scope) *Client {
	c.scope = s
	return c
}

// WithRateLimit paces every request to at most perSecond requests across this
// client and all clones made from it afterwards. A non-positive value imposes no
// limit (the default).
func (c *Client) WithRateLimit(perSecond float64) *Client {
	c.throttle = newThrottle(perSecond)
	return c
}

// WithHeaders sets default headers for all requests.
func (c *Client) WithHeaders(headers map[string]string) *Client {
	for k, v := range headers {
		c.headers[k] = v
	}
	return c
}

// WithCookies sets cookies for all requests.
func (c *Client) WithCookies(cookies string) *Client {
	c.cookies = cookies
	return c
}

// WithProxy sets the proxy URL.
func (c *Client) WithProxy(proxyURL string) *Client {
	c.proxyURL = proxyURL
	c.rebuildNeeded()
	return c
}

// WithTimeout sets the request timeout.
func (c *Client) WithTimeout(timeout time.Duration) *Client {
	c.timeout = timeout
	c.rebuildNeeded()
	return c
}

// WithFollowRedirects sets whether to follow redirects.
func (c *Client) WithFollowRedirects(follow bool) *Client {
	c.followRedirects = follow
	c.rebuildNeeded()
	return c
}

// WithUserAgent sets the User-Agent header.
func (c *Client) WithUserAgent(ua string) *Client {
	c.userAgent = ua
	return c
}

// ClientSnapshot is a read-only view of the per-scan client settings, used
// by detectors that need to mirror the same proxy/headers/cookies/UA/insecure
// plumbing on a parallel transport (e.g. raw WebSocket dials).
type ClientSnapshot struct {
	Headers   map[string]string
	Cookies   string
	UserAgent string
	ProxyURL  string
	Insecure  bool
}

// Snapshot returns a copy of the client's per-scan settings. Useful for
// detectors that don't speak HTTP through this client (e.g. WebSocket,
// raw smuggling) but still need to honor the global plumbing.
func (c *Client) Snapshot() ClientSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	hdrs := make(map[string]string, len(c.headers))
	for k, v := range c.headers {
		hdrs[k] = v
	}
	return ClientSnapshot{
		Headers:   hdrs,
		Cookies:   c.cookies,
		UserAgent: c.userAgent,
		ProxyURL:  c.proxyURL,
		Insecure:  c.insecure,
	}
}

// HasAuth reports whether this client is carrying any kind of authentication
// (Cookie or Authorization header). Detectors use it to decide whether
// "anonymous-still-works" is meaningful — without baseline auth, the
// answer is trivially yes and not worth reporting.
func (c *Client) HasAuth() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cookies != "" {
		return true
	}
	for k := range c.headers {
		if strings.EqualFold(k, "Authorization") {
			return true
		}
	}
	return false
}

// WithInsecure disables TLS certificate verification.
func (c *Client) WithInsecure(insecure bool) *Client {
	c.insecure = insecure
	c.rebuildNeeded()
	return c
}

// ForParam returns a lightweight clone whose SendPayload dispatches through
// SendPayloadAt for the given parameter. Use this in the scanner to create
// a per-parameter client before passing it to any detector — every detector's
// SendPayload call then transparently reaches the right injection point
// (JSON body, path segment, header, XML, cookie) without changing the
// detector's own code.
//
// The clone shares the underlying http.Client, throttle, cookie source, and
// scope with the parent, so it is cheap to create per-parameter. It only
// differs in the paramOverride and siblingParams fields.
func (c *Client) ForParam(p core.Parameter) *Client {
	cloned := c.Clone()
	cloned.paramOverride = &p
	return cloned
}

// WithSiblings attaches sibling body params from the same endpoint.
// SendPayloadInJSON includes them with default values in every request.
func (c *Client) WithSiblings(siblings []core.Parameter) *Client {
	c.siblingParams = siblings
	return c
}

// rebuildNeeded marks the HTTP client as needing reconstruction.
// The actual rebuild is deferred to avoid redundant rebuilds during chained calls.
func (c *Client) rebuildNeeded() {
	c.mu.Lock()
	c.httpClient = nil
	c.mu.Unlock()
}

// ensureClient builds the HTTP client if not yet built. Thread-safe.
func (c *Client) ensureClient() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.httpClient == nil {
		c.buildHTTPClient()
	}
}

// client_safety.go — WAF-block detection, lockout detection, and
// connection-error tracking accessors.
package http

import (
	"net/url"
	"strings"
	"sync/atomic"
)

// WAFBlocks returns the current consecutive WAF-block count.
func (c *Client) WAFBlocks() int {
	return int(atomic.LoadInt32(&c.wafBlocks))
}

// ConnErrors returns the current consecutive connection-error count.
func (c *Client) ConnErrors() int {
	return int(atomic.LoadInt32(&c.connErrors))
}

// LockoutDetected reports whether the client has seen a probable account-lockout
// response. Detectors should check this before sending auth probes.
func (c *Client) LockoutDetected() bool {
	return atomic.LoadInt32(&c.lockoutDetected) != 0
}

// isWAFBlock heuristically identifies a response as a WAF block page.
func isWAFBlock(r *Response) bool {
	if r.StatusCode == 429 {
		return true
	}
	if _, ok := r.Headers["Retry-After"]; ok {
		return true
	}
	if r.StatusCode == 403 {
		lower := strings.ToLower(r.Body)
		for _, sig := range wafSignatures {
			if strings.Contains(lower, sig) {
				return true
			}
		}
	}
	return false
}

var wafSignatures = []string{
	"blocked", "access denied", "cloudflare", "akamai",
	"imperva", "sucuri", "mod_security", "web application firewall",
	"rate limit", "captcha", "challenge-platform", "ddos protection",
}

// isLoginURL reports whether the URL path looks like an authentication endpoint.
func isLoginURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	p := strings.ToLower(u.Path)
	return strings.Contains(p, "login") || strings.Contains(p, "signin") ||
		strings.Contains(p, "auth") || strings.Contains(p, "token") ||
		strings.Contains(p, "oauth")
}

// isLockoutResponse checks for lockout indicators in the response.
func isLockoutResponse(r *Response) bool {
	if r.StatusCode == 429 {
		return true
	}
	lower := strings.ToLower(r.Body)
	for _, sig := range lockoutSignatures {
		if strings.Contains(lower, sig) {
			return true
		}
	}
	return false
}

var lockoutSignatures = []string{
	"locked", "too many attempts", "account locked",
	"temporarily disabled", "too many requests",
	"maximum login attempts", "account suspended",
}

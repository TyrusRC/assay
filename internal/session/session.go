// Package session keeps an authenticated scan alive. It holds the current
// cookie behind a lock, detects when the target logs the scanner out, and
// re-authenticates — so authenticated probes do not silently degrade to
// unauthenticated, the classic source of false negatives on the highest-value
// classes. http.Client reads the live cookie through WithCookieSource, so one
// re-auth updates every client that shares the source.
package session

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/TyrusRC/assay/internal/http"
)

// ReauthFunc performs a fresh login and returns the new cookie string.
type ReauthFunc func(ctx context.Context) (string, error)

// Session is a live, re-authenticating scan session.
type Session struct {
	mu        sync.RWMutex
	cookie    string
	reauths   int
	reauth    ReauthFunc
	canaryURL string // an authenticated-only URL used to detect logout
	marker    string // substring present only while authenticated (e.g. --login-success)
}

// New builds a Session. cookie is the initial login cookie, reauth re-runs the
// login, canaryURL is an authenticated-only URL to poll, and marker is a string
// present in its response only while authenticated. Keepalive is a no-op unless
// both canaryURL and reauth are set.
func New(cookie string, reauth ReauthFunc, canaryURL, marker string) *Session {
	return &Session{cookie: cookie, reauth: reauth, canaryURL: canaryURL, marker: marker}
}

// Cookie returns the current session cookie. It is the callback for
// http.Client.WithCookieSource.
func (s *Session) Cookie() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cookie
}

// Reauths reports how many times the session was re-authenticated.
func (s *Session) Reauths() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.reauths
}

// Alive fetches the canary URL and reports whether the session still shows an
// authenticated state. With no canary it assumes alive. A transport error is
// not treated as a logout (it is not evidence of one).
func (s *Session) Alive(ctx context.Context, client *http.Client) bool {
	if s.canaryURL == "" {
		return true
	}
	resp, err := client.Get(ctx, s.canaryURL)
	if err != nil || resp == nil {
		return true
	}
	return s.authenticated(resp)
}

// authenticated decides from a canary response whether the session is still
// logged in. A 401/403 is a logout. With a marker set, its presence decides.
// Without a marker, a login-looking final URL or Location header is a logout.
func (s *Session) authenticated(resp *http.Response) bool {
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return false
	}
	if s.marker != "" {
		return strings.Contains(resp.Body, s.marker)
	}
	if looksLikeLogin(resp.URL) {
		return false
	}
	if loc := resp.Headers["Location"]; loc != "" && looksLikeLogin(loc) {
		return false
	}
	return true
}

func looksLikeLogin(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "login") || strings.Contains(l, "signin") ||
		strings.Contains(l, "sign-in") || strings.Contains(l, "/auth")
}

// Reauth re-runs login and swaps in the new cookie, returning it.
func (s *Session) Reauth(ctx context.Context) (string, error) {
	if s.reauth == nil {
		return s.Cookie(), nil
	}
	cookie, err := s.reauth(ctx)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.cookie = cookie
	s.reauths++
	s.mu.Unlock()
	return cookie, nil
}

// Keepalive polls the canary every interval until ctx is cancelled, and
// re-authenticates when the session has dropped. onEvent, when non-nil, receives
// a human-readable note on each re-auth or failure. It is a no-op without both a
// canary and a reauth function.
func (s *Session) Keepalive(ctx context.Context, client *http.Client, interval time.Duration, onEvent func(string)) {
	if s.canaryURL == "" || s.reauth == nil {
		return
	}
	if interval <= 0 {
		interval = 60 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.Alive(ctx, client) {
				continue
			}
			if _, err := s.Reauth(ctx); err != nil {
				if onEvent != nil {
					onEvent("session expired and re-authentication failed: " + err.Error())
				}
				continue
			}
			if onEvent != nil {
				onEvent("session expired mid-scan; re-authenticated")
			}
		}
	}
}

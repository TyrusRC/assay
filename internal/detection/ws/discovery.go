package ws

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// wsURLPattern catches `ws://...` and `wss://...` URLs in HTML/JS bodies.
var wsURLPattern = regexp.MustCompile(`(?i)\b(wss?://[a-z0-9\-._:/?#@!$&'()*+,;=%~]+)`)

// constructorPattern catches `new WebSocket("...")` (and single-quoted) in JS
// where the URL is sometimes a relative path that needs upgrading to ws/wss.
var constructorPattern = regexp.MustCompile(`(?i)new\s+WebSocket\s*\(\s*['"]([^'"]+)['"]`)

// commonPaths lists candidate WS endpoints to probe even when the page
// gives no hint. Kept conservative — too many guesses produces noise.
// "/" is included because some WS-only servers (echo.websocket.events,
// internal pubsub services) accept upgrades at the root path.
var commonPaths = []string{"/", "/ws", "/wss", "/websocket", "/socket", "/socket.io/?EIO=4&transport=websocket", "/chat", "/livechat", "/realtime", "/notifications", "/api/ws"}

// discoverEndpoints fetches the target page and extracts WS URLs from the
// HTML/JS body, then augments them with a small list of common paths.
// Duplicates are removed. All returned URLs use ws:// or wss:// schemes.
func (d *Detector) discoverEndpoints(ctx context.Context, target string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(u string) {
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		out = append(out, u)
	}

	resp, err := d.client.Get(ctx, target)
	if err == nil && resp != nil {
		body := resp.Body
		for _, m := range wsURLPattern.FindAllStringSubmatch(body, -1) {
			add(m[1])
		}
		for _, m := range constructorPattern.FindAllStringSubmatch(body, -1) {
			if u := upgradeToWS(target, m[1]); u != "" {
				add(u)
			}
		}
	}

	// Probe the target URL itself first — many WS-only services accept
	// upgrades at whatever path the user gave us (echo.websocket.events,
	// k8s pubsub, etc). Then fan out to common paths under the same host.
	if base, _ := url.Parse(target); base != nil && base.Host != "" {
		scheme := "ws"
		if base.Scheme == "https" {
			scheme = "wss"
		}
		// Target URL with its actual path.
		path := base.Path
		if path == "" {
			path = "/"
		}
		add(scheme + "://" + base.Host + path)
		for _, p := range commonPaths {
			add(scheme + "://" + base.Host + p)
		}
	}

	return out
}

// upgradeToWS turns a relative or http/https URL into a ws/wss URL, using
// the target's scheme/host as the base. Returns "" for unparseable input.
func upgradeToWS(targetURL, raw string) string {
	if strings.HasPrefix(raw, "ws://") || strings.HasPrefix(raw, "wss://") {
		return raw
	}
	base, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}
	rel, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(rel)
	switch resolved.Scheme {
	case "https":
		resolved.Scheme = "wss"
	case "http", "":
		resolved.Scheme = "ws"
	}
	return resolved.String()
}

// Compile-time symbol use to keep the http import live (Detector references it).
var _ = (*http.Client)(nil)

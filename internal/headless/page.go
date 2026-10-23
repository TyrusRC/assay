package headless

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
)

// CapturedRequest is one XHR or fetch a page issued while loading.
type CapturedRequest struct {
	URL    string `json:"url"`
	Method string `json:"method"`
	Type   string `json:"type"` // "XHR" or "Fetch"
}

// Page wraps a single Rod page. Public API mirrors the chromedp-backed
// version it replaces, so detectors compose unchanged.
type Page struct {
	page            *rod.Page // nil-safe: methods short-circuit when zero-value (used by Pool tests that never launch)
	navigateTimeout time.Duration
}

// Navigate loads the URL, blocking until the load event or
// navigateTimeout, whichever is first. Caller-side ctx cancellation
// cancels the wait.
func (p *Page) Navigate(ctx context.Context, url string) error {
	if p == nil || p.page == nil {
		return fmt.Errorf("headless: page not initialised")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	timeout := p.navigateTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	page := p.page.Timeout(timeout).Context(ctx)
	if err := page.Navigate(url); err != nil {
		return err
	}
	return page.WaitLoad()
}

// NavigateAndCapture loads url and records the XHR/fetch requests the page
// issues while loading and for a short settle window after. It surfaces the
// dynamic API endpoints that never appear in the static HTML — the modern
// SPA/API attack surface a static crawl misses. Results are deduped by
// method+URL. The listener is bound to a child context and torn down on return.
func (p *Page) NavigateAndCapture(ctx context.Context, url string, settle time.Duration) ([]CapturedRequest, error) {
	if p == nil || p.page == nil {
		return nil, fmt.Errorf("headless: page not initialised")
	}
	if settle <= 0 {
		settle = 2 * time.Second
	}
	capCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var mu sync.Mutex
	seen := make(map[string]bool)
	var out []CapturedRequest

	// Listen for request events before navigating so load-time XHR/fetch is
	// caught. The goroutine returns when capCtx is cancelled.
	go p.page.Context(capCtx).EachEvent(func(e *proto.NetworkRequestWillBeSent) {
		if e.Request == nil {
			return
		}
		if e.Type != proto.NetworkResourceTypeXHR && e.Type != proto.NetworkResourceTypeFetch {
			return
		}
		key := e.Request.Method + " " + e.Request.URL
		mu.Lock()
		if !seen[key] {
			seen[key] = true
			out = append(out, CapturedRequest{URL: e.Request.URL, Method: e.Request.Method, Type: string(e.Type)})
		}
		mu.Unlock()
	})()

	timeout := p.navigateTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	navPage := p.page.Timeout(timeout).Context(capCtx)
	if err := navPage.Navigate(url); err != nil {
		return nil, err
	}
	_ = navPage.WaitLoad()

	// Let late (post-load) XHR/fetch fire.
	select {
	case <-time.After(settle):
	case <-ctx.Done():
	}
	cancel()

	mu.Lock()
	defer mu.Unlock()
	result := make([]CapturedRequest, len(out))
	copy(result, out)
	return result, nil
}

// CapturedRoutes returns the client-side routes the page registered through the
// History API (pushState/replaceState/popstate), recorded by the page init
// script. Values may be relative — the caller resolves them against the page.
func (p *Page) CapturedRoutes(ctx context.Context) ([]string, error) {
	if p == nil || p.page == nil {
		return nil, fmt.Errorf("headless: page not initialised")
	}
	raw, err := p.EvalJS(ctx, `JSON.stringify(window.__assayRoutes || [])`)
	if err != nil {
		return nil, err
	}
	var routes []string
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &routes); err != nil {
			return nil, err
		}
	}
	return routes, nil
}

// EvalJS evaluates a JavaScript expression in the page and returns the
// result as a string. Numbers/objects are JSON-encoded for stability;
// strings are returned unquoted.
//
// Rod's Eval expects a function literal — bare expressions like `"hi"`
// throw `TypeError: "hi".apply is not a function`. We wrap the caller's
// expression as `() => (expr)` so existing call sites keep passing plain
// JS like `window.name` or `JSON.stringify(...)` and still get the
// chromedp-era semantics.
func (p *Page) EvalJS(ctx context.Context, expr string) (string, error) {
	if p == nil || p.page == nil {
		return "", fmt.Errorf("headless: page not initialised")
	}
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}
	wrapped := "() => (" + expr + ")"
	res, err := p.page.Context(ctx).Eval(wrapped)
	if err != nil {
		return "", err
	}
	if res == nil {
		return "", nil
	}
	// Strings come back unquoted; numbers, bools, objects come back as
	// JSON-encoded text. gson.JSON.Str() returns "" for non-string values,
	// so we use the JSON projection as a discriminator: a JSON-encoded
	// string starts and ends with `"`, anything else (numbers, true/false,
	// null, {…}, […]) does not.
	v := res.Value
	raw := v.JSON("", "")
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		var unquoted string
		if err := json.Unmarshal([]byte(raw), &unquoted); err == nil {
			return unquoted, nil
		}
	}
	return raw, nil
}

// GetLocalStorage returns all localStorage key-value pairs.
func (p *Page) GetLocalStorage(ctx context.Context) (map[string]string, error) {
	return p.getStorageData(ctx, "localStorage")
}

// SetLocalStorage sets one localStorage entry.
func (p *Page) SetLocalStorage(ctx context.Context, key, value string) error {
	expr := fmt.Sprintf(`localStorage.setItem(%q, %q)`, key, value)
	_, err := p.EvalJS(ctx, expr)
	return err
}

// GetSessionStorage returns all sessionStorage key-value pairs.
func (p *Page) GetSessionStorage(ctx context.Context) (map[string]string, error) {
	return p.getStorageData(ctx, "sessionStorage")
}

// SetSessionStorage sets one sessionStorage entry.
func (p *Page) SetSessionStorage(ctx context.Context, key, value string) error {
	expr := fmt.Sprintf(`sessionStorage.setItem(%q, %q)`, key, value)
	_, err := p.EvalJS(ctx, expr)
	return err
}

// GetCookies returns document.cookie parsed into a map. Note: this only
// surfaces cookies visible to JS — HttpOnly cookies are excluded by
// design. If a future detector needs HttpOnly access we can switch to
// the CDP-level `network.GetCookies` instead.
func (p *Page) GetCookies(ctx context.Context) (map[string]string, error) {
	if p == nil || p.page == nil {
		return nil, fmt.Errorf("headless: page not initialised")
	}
	cookieStr, err := p.EvalJS(ctx, `document.cookie`)
	if err != nil {
		return nil, err
	}

	cookies := make(map[string]string)
	if cookieStr == "" {
		return cookies, nil
	}
	for _, pair := range splitCookieString(cookieStr) {
		if pair[0] != "" {
			cookies[pair[0]] = pair[1]
		}
	}
	return cookies, nil
}

// SetCookie sets a cookie via document.cookie. JS-visible only.
func (p *Page) SetCookie(ctx context.Context, name, value string) error {
	expr := fmt.Sprintf(`document.cookie = %q`, name+"="+value)
	_, err := p.EvalJS(ctx, expr)
	return err
}

// GetWindowName returns window.name.
func (p *Page) GetWindowName(ctx context.Context) (string, error) {
	return p.EvalJS(ctx, `window.name`)
}

// SetWindowName sets window.name.
func (p *Page) SetWindowName(ctx context.Context, value string) error {
	expr := fmt.Sprintf(`window.name = %q`, value)
	_, err := p.EvalJS(ctx, expr)
	return err
}

// close releases the underlying rod.Page. Safe to call on a zero-value
// Page (the Pool concurrency tests construct &Page{} literally).
func (p *Page) close() {
	if p == nil || p.page == nil {
		return
	}
	_ = p.page.Close()
	p.page = nil
}

// getStorageData extracts a Web Storage area into a Go map.
func (p *Page) getStorageData(ctx context.Context, storageName string) (map[string]string, error) {
	expr := fmt.Sprintf(`(function() {
		var result = {};
		for (var i = 0; i < %s.length; i++) {
			var key = %s.key(i);
			result[key] = %s.getItem(key);
		}
		return JSON.stringify(result);
	})()`, storageName, storageName, storageName)

	jsonStr, err := p.EvalJS(ctx, expr)
	if err != nil {
		return nil, err
	}
	result := make(map[string]string)
	if jsonStr == "" {
		return result, nil
	}
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, err
	}
	return result, nil
}

// splitCookieString splits "key1=val1; key2=val2" into pairs.
func splitCookieString(s string) [][2]string {
	var pairs [][2]string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ';' {
			pair := parseCookiePair(s[start:i])
			pairs = append(pairs, pair)
			start = i + 1
			if start < len(s) && s[start] == ' ' {
				start++
			}
		}
	}
	if start < len(s) {
		pair := parseCookiePair(s[start:])
		pairs = append(pairs, pair)
	}
	return pairs
}

func parseCookiePair(s string) [2]string {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return [2]string{s[:i], s[i+1:]}
		}
	}
	return [2]string{s, ""}
}

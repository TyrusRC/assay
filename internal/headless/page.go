package headless

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-rod/rod"
)

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

// GetDOM returns the outer HTML of the document.
func (p *Page) GetDOM(ctx context.Context) (string, error) {
	if p == nil || p.page == nil {
		return "", fmt.Errorf("headless: page not initialised")
	}
	html, err := p.page.Context(ctx).HTML()
	if err != nil {
		return "", err
	}
	return html, nil
}

// Reset returns the page to about:blank.
func (p *Page) Reset(ctx context.Context) error {
	return p.Navigate(ctx, "about:blank")
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

package headless

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/chromedp/chromedp"
)

// Page represents a single browser page with navigation and storage helpers.
// All chromedp operations use the page's internal browser context.
// The ctx parameter on public methods is used for caller-side cancellation.
type Page struct {
	ctx             context.Context
	cancel          context.CancelFunc
	navigateTimeout time.Duration
}

// runWithCaller creates a derived context that cancels if the caller's context
// is cancelled, but still carries the chromedp browser binding.
func (p *Page) runWithCaller(caller context.Context, actions ...chromedp.Action) error {
	// If caller context is already done, fail fast
	select {
	case <-caller.Done():
		return caller.Err()
	default:
	}
	return chromedp.Run(p.ctx, actions...)
}

// Navigate loads the specified URL in the browser page.
func (p *Page) Navigate(ctx context.Context, url string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	navCtx, cancel := context.WithTimeout(p.ctx, p.navigateTimeout)
	defer cancel()

	return chromedp.Run(navCtx, chromedp.Navigate(url))
}

// EvalJS evaluates a JavaScript expression and returns the result as a string.
func (p *Page) EvalJS(ctx context.Context, expr string) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	var result interface{}
	err := chromedp.Run(p.ctx, chromedp.Evaluate(expr, &result))
	if err != nil {
		return "", err
	}
	if result == nil {
		return "", nil
	}
	switch v := result.(type) {
	case string:
		return v, nil
	default:
		b, marshalErr := json.Marshal(v)
		if marshalErr != nil {
			return fmt.Sprintf("%v", v), nil
		}
		return string(b), nil
	}
}

// GetLocalStorage returns all localStorage key-value pairs.
func (p *Page) GetLocalStorage(ctx context.Context) (map[string]string, error) {
	return p.getStorageData(ctx, "localStorage")
}

// SetLocalStorage sets a key-value pair in localStorage.
func (p *Page) SetLocalStorage(ctx context.Context, key, value string) error {
	expr := fmt.Sprintf(`localStorage.setItem(%q, %q)`, key, value)
	return p.runWithCaller(ctx, chromedp.Evaluate(expr, nil))
}

// GetSessionStorage returns all sessionStorage key-value pairs.
func (p *Page) GetSessionStorage(ctx context.Context) (map[string]string, error) {
	return p.getStorageData(ctx, "sessionStorage")
}

// SetSessionStorage sets a key-value pair in sessionStorage.
func (p *Page) SetSessionStorage(ctx context.Context, key, value string) error {
	expr := fmt.Sprintf(`sessionStorage.setItem(%q, %q)`, key, value)
	return p.runWithCaller(ctx, chromedp.Evaluate(expr, nil))
}

// GetCookies returns all cookies as a key-value map.
func (p *Page) GetCookies(ctx context.Context) (map[string]string, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	var result string
	err := chromedp.Run(p.ctx, chromedp.Evaluate(`document.cookie`, &result))
	if err != nil {
		return nil, err
	}

	cookies := make(map[string]string)
	if result == "" {
		return cookies, nil
	}

	for _, pair := range splitCookieString(result) {
		if pair[0] != "" {
			cookies[pair[0]] = pair[1]
		}
	}
	return cookies, nil
}

// SetCookie sets a cookie via document.cookie.
func (p *Page) SetCookie(ctx context.Context, name, value string) error {
	expr := fmt.Sprintf(`document.cookie = %q`, name+"="+value)
	return p.runWithCaller(ctx, chromedp.Evaluate(expr, nil))
}

// GetWindowName returns the current window.name value.
func (p *Page) GetWindowName(ctx context.Context) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	var result string
	err := chromedp.Run(p.ctx, chromedp.Evaluate(`window.name`, &result))
	return result, err
}

// SetWindowName sets the window.name value.
func (p *Page) SetWindowName(ctx context.Context, value string) error {
	expr := fmt.Sprintf(`window.name = %q`, value)
	return p.runWithCaller(ctx, chromedp.Evaluate(expr, nil))
}

// GetDOM returns the outer HTML of the document.
func (p *Page) GetDOM(ctx context.Context) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	var html string
	err := chromedp.Run(p.ctx, chromedp.OuterHTML("html", &html))
	return html, err
}

// Reset clears page state by navigating to about:blank and clearing storage.
func (p *Page) Reset(ctx context.Context) error {
	return p.runWithCaller(ctx, chromedp.Navigate("about:blank"))
}

// close cancels the browser context.
func (p *Page) close() {
	if p.cancel != nil {
		p.cancel()
	}
}

// getStorageData extracts all key-value pairs from the given storage object.
func (p *Page) getStorageData(ctx context.Context, storageName string) (map[string]string, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	expr := fmt.Sprintf(`(function() {
		var result = {};
		for (var i = 0; i < %s.length; i++) {
			var key = %s.key(i);
			result[key] = %s.getItem(key);
		}
		return JSON.stringify(result);
	})()`, storageName, storageName, storageName)

	var jsonStr string
	err := chromedp.Run(p.ctx, chromedp.Evaluate(expr, &jsonStr))
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
			// Skip space after semicolon
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

// parseCookiePair splits "key=value" into [key, value].
func parseCookiePair(s string) [2]string {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return [2]string{s[:i], s[i+1:]}
		}
	}
	return [2]string{s, ""}
}

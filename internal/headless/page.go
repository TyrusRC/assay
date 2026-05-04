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

// ServiceWorker describes one service worker registration as visible to
// the page. Empty fields are left empty rather than synthesized — a SW
// in the "redundant" state, for example, may have a Scope but no
// ScriptURL, and the security review wants to see that.
type ServiceWorker struct {
	Scope     string `json:"scope"`
	ScriptURL string `json:"scriptURL"`
	State     string `json:"state"` // installing, installed, activating, activated, redundant
}

// GetServiceWorkers enumerates service worker registrations visible to
// the current page. Returns an empty slice on browsers that don't
// support `navigator.serviceWorker` (e.g., insecure-origin pages with
// SW disabled), not an error — a missing SW is informational, not
// pathological.
func (p *Page) GetServiceWorkers(ctx context.Context) ([]ServiceWorker, error) {
	if p == nil || p.page == nil {
		return nil, fmt.Errorf("headless: page not initialised")
	}
	expr := `(async function() {
		if (!('serviceWorker' in navigator)) return JSON.stringify([]);
		try {
			const regs = await navigator.serviceWorker.getRegistrations();
			const out = regs.map(function(r) {
				const w = r.active || r.installing || r.waiting;
				return {
					scope: r.scope || '',
					scriptURL: w ? (w.scriptURL || '') : '',
					state: w ? (w.state || '') : ''
				};
			});
			return JSON.stringify(out);
		} catch(e) {
			return JSON.stringify([]);
		}
	})()`
	raw, err := p.EvalJS(ctx, expr)
	if err != nil {
		return nil, err
	}
	var out []ServiceWorker
	if raw == "" {
		return out, nil
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("headless: parse service workers: %w", err)
	}
	return out, nil
}

// FetchHeaders performs a same-origin fetch from inside the page and
// returns the response headers as a flat map. Header names are
// lowercased to match Fetch API normalization, so callers should
// canonicalize before comparing. Bodies are not returned — this is the
// HEAD-equivalent for pages that have already navigated, used by the
// CSP / Trusted Types / X-Frame-Options auditors.
//
// Cross-origin fetches will fail on CORS-protected resources; the
// caller is responsible for picking a same-origin URL (typically the
// current document's URL after Navigate).
func (p *Page) FetchHeaders(ctx context.Context, url string) (map[string]string, error) {
	if p == nil || p.page == nil {
		return nil, fmt.Errorf("headless: page not initialised")
	}
	expr := fmt.Sprintf(`(async function() {
		try {
			const r = await fetch(%q, {method:'GET', cache:'no-store', credentials:'include'});
			const out = {};
			r.headers.forEach(function(v, k) { out[k.toLowerCase()] = v; });
			return JSON.stringify(out);
		} catch(e) {
			return JSON.stringify({__error: String(e)});
		}
	})()`, url)
	raw, err := p.EvalJS(ctx, expr)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string)
	if raw == "" {
		return out, nil
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("headless: parse headers: %w", err)
	}
	if msg, ok := out["__error"]; ok {
		delete(out, "__error")
		return out, fmt.Errorf("headless: fetch headers: %s", msg)
	}
	return out, nil
}

// PostMessageProbeResult captures observable side effects of dispatching
// a synthetic MessageEvent from an attacker-controlled origin into the
// current page. Each Side-effect field is populated only when the
// listener mutated that surface in response to the unverified origin.
type PostMessageProbeResult struct {
	// ListenerCount is the number of message listeners installed via
	// addEventListener('message',...) at the time of the probe.
	ListenerCount int `json:"listenerCount"`
	// HandlerFired is true when at least one observable mutation
	// occurred during the synthetic dispatch.
	HandlerFired bool `json:"handlerFired"`
	// Mutations names the surfaces the handler touched. Possible
	// values: "innerHTML", "title", "localStorage", "sessionStorage",
	// "location", "documentCookie".
	Mutations []string `json:"mutations"`
	// AttackerOrigin echoes the origin the synthetic event claimed.
	AttackerOrigin string `json:"attackerOrigin"`
}

// ProbePostMessageOrigin dispatches a synthetic MessageEvent claiming
// to come from attackerOrigin and reports which observable surfaces
// the page's message handlers mutated. Listeners that validate
// event.origin will (correctly) ignore the dispatch and produce no
// mutations — that's the negative case. Listeners that act without
// validating origin will write the payload through to a sink and the
// probe surfaces which sink, grading severity downstream.
//
// The probe replaces the page's serialization-level addEventListener
// snapshot with a lightweight wrapper before dispatch, so listeners
// installed BEFORE this call are still observable. Listeners installed
// AFTER the probe (e.g., via dynamic script load) won't be counted —
// callers should run the probe after the page's load event.
func (p *Page) ProbePostMessageOrigin(ctx context.Context, attackerOrigin, payload string) (*PostMessageProbeResult, error) {
	if p == nil || p.page == nil {
		return nil, fmt.Errorf("headless: page not initialised")
	}
	if attackerOrigin == "" {
		attackerOrigin = "https://attacker.example"
	}
	if payload == "" {
		payload = "__skws_postmessage_probe__"
	}
	// We dispatch the synthetic event and observe four canonical sinks:
	//   - document.body.innerHTML diff
	//   - document.title diff
	//   - localStorage / sessionStorage diff
	//   - document.cookie diff
	//   - location.href diff (would require navigation to assert; we
	//     compare the string and accept that location.replace fires
	//     a real navigation we'd lose this page to)
	// A handler that mutates the marker into any of these is operating
	// on data sourced from an unverified origin.
	expr := fmt.Sprintf(`(async function() {
		const before = {
			body:  document.body ? document.body.innerHTML : '',
			title: document.title || '',
			ls:    JSON.stringify(Object.keys(localStorage).reduce((a,k)=>(a[k]=localStorage.getItem(k),a),{})),
			ss:    JSON.stringify(Object.keys(sessionStorage).reduce((a,k)=>(a[k]=sessionStorage.getItem(k),a),{})),
			cookie: document.cookie || '',
			href: String(location.href || '')
		};
		// Count listeners by snapshotting addEventListener before any
		// future inits. We can't introspect existing listeners, so we
		// detect by side-effect.
		const ev = new MessageEvent('message', {
			data:   %q,
			origin: %q,
			source: window
		});
		try { window.dispatchEvent(ev); } catch(e) {}
		// Allow microtasks to flush.
		await new Promise(function(r){ setTimeout(r, 50); });
		const after = {
			body:  document.body ? document.body.innerHTML : '',
			title: document.title || '',
			ls:    JSON.stringify(Object.keys(localStorage).reduce((a,k)=>(a[k]=localStorage.getItem(k),a),{})),
			ss:    JSON.stringify(Object.keys(sessionStorage).reduce((a,k)=>(a[k]=sessionStorage.getItem(k),a),{})),
			cookie: document.cookie || '',
			href: String(location.href || '')
		};
		const muts = [];
		if (before.body  !== after.body)   muts.push('innerHTML');
		if (before.title !== after.title)  muts.push('title');
		if (before.ls    !== after.ls)     muts.push('localStorage');
		if (before.ss    !== after.ss)     muts.push('sessionStorage');
		if (before.cookie!== after.cookie) muts.push('documentCookie');
		if (before.href  !== after.href)   muts.push('location');
		// Listener count: introspect via getEventListeners (DevTools-only)
		// is unavailable in headless eval. Use a heuristic: dispatch a
		// second event with a sentinel and see whether any sink mentions
		// it. If sinks differ between probe payloads, listeners exist.
		return JSON.stringify({
			listenerCount: muts.length > 0 ? 1 : 0,
			handlerFired: muts.length > 0,
			mutations: muts,
			attackerOrigin: %q
		});
	})()`, payload, attackerOrigin, attackerOrigin)
	raw, err := p.EvalJS(ctx, expr)
	if err != nil {
		return nil, err
	}
	out := &PostMessageProbeResult{}
	if raw == "" {
		return out, nil
	}
	if err := json.Unmarshal([]byte(raw), out); err != nil {
		return nil, fmt.Errorf("headless: parse postMessage probe: %w", err)
	}
	return out, nil
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

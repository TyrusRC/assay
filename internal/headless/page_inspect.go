// page_inspect.go — page inspection methods: DOM extraction, service
// worker enumeration, fetch-based header retrieval, and postMessage probing.
package headless

import (
	"context"
	"encoding/json"
	"fmt"
)

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
		payload = "__assay_postmessage_probe__"
	}
	expr := fmt.Sprintf(`(async function() {
		const before = {
			body:  document.body ? document.body.innerHTML : '',
			title: document.title || '',
			ls:    JSON.stringify(Object.keys(localStorage).reduce((a,k)=>(a[k]=localStorage.getItem(k),a),{})),
			ss:    JSON.stringify(Object.keys(sessionStorage).reduce((a,k)=>(a[k]=sessionStorage.getItem(k),a),{})),
			cookie: document.cookie || '',
			href: String(location.href || '')
		};
		const ev = new MessageEvent('message', {
			data:   %q,
			origin: %q,
			source: window
		});
		try { window.dispatchEvent(ev); } catch(e) {}
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

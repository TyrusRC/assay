package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// LoginPage is the headless-browser surface a headless login needs. It is
// satisfied by *headless.Page and faked in tests, so the login orchestration is
// verifiable without a real browser.
type LoginPage interface {
	Navigate(ctx context.Context, url string) error
	EvalJS(ctx context.Context, expr string) (string, error)
	GetCookies(ctx context.Context) (map[string]string, error)
}

// HeadlessLogin performs a JavaScript-driven login: it navigates a login page
// in a real browser, fills the credentials, submits, and captures the resulting
// session cookies. This handles SPA/JS logins that the HTTP FormLogin cannot,
// because the page authenticates via client-side fetch/XHR rather than a plain
// form POST.
type HeadlessLogin struct {
	// LoginURL is the page carrying the login form.
	LoginURL string
	// Username and Password are the credentials to submit.
	Username string
	Password string
	// UserSelector/PassSelector/SubmitSelector are optional CSS selectors. When
	// empty, the fields are auto-detected from common input shapes.
	UserSelector   string
	PassSelector   string
	SubmitSelector string
	// Success is an optional substring expected in the post-login page body to
	// confirm authentication succeeded.
	Success string
	// WaitMillis is how long to wait after submitting for the login XHR and any
	// navigation to settle before capturing cookies (default 1500ms).
	WaitMillis int
}

// defaultLoginWaitMillis is the post-submit settle time when none is configured.
const defaultLoginWaitMillis = 1500

// Validate checks that the minimum configuration is present.
func (h HeadlessLogin) Validate() error {
	if strings.TrimSpace(h.LoginURL) == "" {
		return fmt.Errorf("headless login: login URL is required")
	}
	if h.Username == "" || h.Password == "" {
		return fmt.Errorf("headless login: username and password are required")
	}
	return nil
}

// Do runs the headless login against page and returns the captured session.
func (h HeadlessLogin) Do(ctx context.Context, page LoginPage) (*Result, error) {
	if err := h.Validate(); err != nil {
		return nil, err
	}
	if err := page.Navigate(ctx, h.LoginURL); err != nil {
		return nil, fmt.Errorf("navigate to login page: %w", err)
	}

	out, err := page.EvalJS(ctx, h.buildFillScript())
	if err != nil {
		return nil, fmt.Errorf("fill login form: %w", err)
	}
	if strings.HasPrefix(out, "missing:") {
		return nil, fmt.Errorf("headless login: could not find the %s field; pass an explicit selector",
			strings.TrimPrefix(out, "missing:"))
	}

	h.settle()

	if h.Success != "" {
		body, berr := page.EvalJS(ctx, `(document.body ? document.body.innerText : "")`)
		if berr == nil && !strings.Contains(body, h.Success) {
			return nil, fmt.Errorf("headless login: success marker %q not found after submit", h.Success)
		}
	}

	cookies, err := page.GetCookies(ctx)
	if err != nil {
		return nil, fmt.Errorf("read session cookies: %w", err)
	}
	header := cookieMapToHeader(cookies)
	if header == "" {
		return nil, fmt.Errorf("headless login: no session cookies were set (login likely failed)")
	}
	return &Result{Cookies: header}, nil
}

// settle waits for the post-submit login flow to complete.
func (h HeadlessLogin) settle() {
	wait := h.WaitMillis
	if wait < 0 {
		return
	}
	if wait == 0 {
		wait = defaultLoginWaitMillis
	}
	time.Sleep(time.Duration(wait) * time.Millisecond)
}

// buildFillScript returns JS that fills the credential fields, dispatches the
// input/change events frameworks listen for, and submits the form. It returns
// "ok" on success or "missing:<field>" when a required field is absent.
func (h HeadlessLogin) buildFillScript() string {
	userSel := jsString(h.selectorOr(h.UserSelector, autoUserSelector))
	passSel := jsString(h.selectorOr(h.PassSelector, autoPassSelector))
	submitSel := jsString(h.selectorOr(h.SubmitSelector, autoSubmitSelector))

	return fmt.Sprintf(`(function(){
  var u = document.querySelector(%s);
  if (!u) { return "missing:username"; }
  var p = document.querySelector(%s);
  if (!p) { return "missing:password"; }
  function setVal(el, val){
    el.focus();
    el.value = val;
    el.dispatchEvent(new Event('input', {bubbles:true}));
    el.dispatchEvent(new Event('change', {bubbles:true}));
  }
  setVal(u, %s);
  setVal(p, %s);
  var btn = document.querySelector(%s);
  if (btn) { btn.click(); }
  else if (p.form) {
    if (p.form.requestSubmit) { p.form.requestSubmit(); } else { p.form.submit(); }
  }
  return "ok";
})()`, userSel, passSel, jsString(h.Username), jsString(h.Password), submitSel)
}

// Auto-detection selectors for common login forms.
const (
	autoUserSelector   = `input[type="email"], input[name*="user" i], input[name*="email" i], input[id*="user" i], input[id*="email" i], input[type="text"]`
	autoPassSelector   = `input[type="password"]`
	autoSubmitSelector = `button[type="submit"], input[type="submit"], button[name*="login" i], button[id*="login" i]`
)

func (h HeadlessLogin) selectorOr(sel, fallback string) string {
	if strings.TrimSpace(sel) != "" {
		return sel
	}
	return fallback
}

// jsString renders s as a valid JS string literal (JSON strings are valid JS).
func jsString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

// cookieMapToHeader renders a cookie map as a deterministic, sorted Cookie
// header value ("a=1; b=2").
func cookieMapToHeader(cookies map[string]string) string {
	if len(cookies) == 0 {
		return ""
	}
	keys := make([]string, 0, len(cookies))
	for k := range cookies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+cookies[k])
	}
	return strings.Join(parts, "; ")
}

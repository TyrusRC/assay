package auth

import (
	"context"
	"strings"
	"testing"
)

// fakePage is an in-memory LoginPage for testing the orchestration without a
// real browser.
type fakePage struct {
	navigated string
	evaled    []string
	cookies   map[string]string
	evalRet   string
	bodyText  string
	navErr    error
	evalErr   error
}

func (p *fakePage) Navigate(_ context.Context, url string) error {
	p.navigated = url
	return p.navErr
}

func (p *fakePage) EvalJS(_ context.Context, expr string) (string, error) {
	p.evaled = append(p.evaled, expr)
	if p.evalErr != nil {
		return "", p.evalErr
	}
	if strings.Contains(expr, "document.body") {
		return p.bodyText, nil
	}
	return p.evalRet, nil
}

func (p *fakePage) GetCookies(_ context.Context) (map[string]string, error) {
	return p.cookies, nil
}

func TestBuildFillScript_IncludesCredentialsAndSelectors(t *testing.T) {
	h := HeadlessLogin{
		LoginURL: "https://app.test/login", Username: "alice", Password: "p@ss\"word",
		UserSelector: "#u", PassSelector: "#p", SubmitSelector: "#go",
	}
	js := h.buildFillScript()
	for _, want := range []string{"#u", "#p", "#go", "alice", "input", "change"} {
		if !strings.Contains(js, want) {
			t.Errorf("fill script missing %q", want)
		}
	}
	// The password must be JS-escaped (the quote should not appear raw-broken).
	if !strings.Contains(js, `p@ss\"word`) {
		t.Errorf("password not JS-escaped in script:\n%s", js)
	}
}

func TestBuildFillScript_AutoDetectsWhenNoSelectors(t *testing.T) {
	h := HeadlessLogin{Username: "a", Password: "b"}
	js := h.buildFillScript()
	if !strings.Contains(js, "type=\\\"password\\\"") && !strings.Contains(js, `password`) {
		t.Errorf("auto-detect script should query a password input:\n%s", js)
	}
}

func TestHeadlessLogin_Do_CapturesCookies(t *testing.T) {
	page := &fakePage{
		evalRet: "ok",
		cookies: map[string]string{"session": "abc", "csrf": "xyz"},
	}
	h := HeadlessLogin{LoginURL: "https://app.test/login", Username: "a", Password: "b", WaitMillis: -1}
	res, err := h.Do(context.Background(), page)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if page.navigated != "https://app.test/login" {
		t.Errorf("expected navigation to login URL, got %q", page.navigated)
	}
	// Cookie header should be deterministic (sorted) and contain both cookies.
	if res.Cookies != "csrf=xyz; session=abc" {
		t.Errorf("unexpected cookie header: %q", res.Cookies)
	}
}

func TestHeadlessLogin_Do_FieldNotFound(t *testing.T) {
	page := &fakePage{evalRet: "missing:password"}
	h := HeadlessLogin{LoginURL: "https://app.test/login", Username: "a", Password: "b", WaitMillis: -1}
	_, err := h.Do(context.Background(), page)
	if err == nil {
		t.Fatal("expected error when a field is not found")
	}
}

func TestHeadlessLogin_Do_SuccessCheckFails(t *testing.T) {
	page := &fakePage{
		evalRet:  "ok",
		bodyText: "Invalid username or password",
		cookies:  map[string]string{"session": "abc"},
	}
	h := HeadlessLogin{LoginURL: "https://app.test/login", Username: "a", Password: "b", Success: "Dashboard", WaitMillis: -1}
	_, err := h.Do(context.Background(), page)
	if err == nil {
		t.Fatal("expected error when success marker is absent")
	}
}

func TestHeadlessLogin_Do_SuccessCheckPasses(t *testing.T) {
	page := &fakePage{
		evalRet:  "ok",
		bodyText: "Welcome to your Dashboard",
		cookies:  map[string]string{"session": "abc"},
	}
	h := HeadlessLogin{LoginURL: "https://app.test/login", Username: "a", Password: "b", Success: "Dashboard", WaitMillis: -1}
	res, err := h.Do(context.Background(), page)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if res.Cookies == "" {
		t.Error("expected captured cookies on success")
	}
}

func TestHeadlessLogin_Validate(t *testing.T) {
	if err := (HeadlessLogin{}).Validate(); err == nil {
		t.Error("expected validation error with no config")
	}
	ok := HeadlessLogin{LoginURL: "https://x/login", Username: "a", Password: "b"}
	if err := ok.Validate(); err != nil {
		t.Errorf("valid config should pass: %v", err)
	}
}

func TestCookieMapToHeader_SortedDeterministic(t *testing.T) {
	got := cookieMapToHeader(map[string]string{"b": "2", "a": "1", "c": "3"})
	if got != "a=1; b=2; c=3" {
		t.Errorf("expected sorted header, got %q", got)
	}
	if cookieMapToHeader(nil) != "" {
		t.Error("nil map should yield empty header")
	}
}

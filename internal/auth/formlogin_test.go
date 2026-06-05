package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// writeString writes s to w, failing the test on error.
func writeString(t *testing.T, w http.ResponseWriter, s string) {
	t.Helper()
	if _, err := w.Write([]byte(s)); err != nil {
		t.Errorf("write response: %v", err)
	}
}

// mustURL parses raw, failing the test on error.
func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

// loginServer serves a CSRF-protected login form, a POST handler that checks
// credentials + CSRF and sets a session cookie, and a protected page.
func loginServer(t *testing.T) *httptest.Server {
	t.Helper()
	const csrf = "tok-123"
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html")
			writeString(t, w, `<html><body>
<form action="/login" method="post">
<input type="hidden" name="csrf" value="`+csrf+`">
<input type="text" name="user">
<input type="password" name="pass">
<button type="submit">Go</button>
</form></body></html>`)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("csrf") != csrf {
			http.Error(w, "bad csrf", http.StatusForbidden)
			return
		}
		if r.PostForm.Get("user") != "alice" || r.PostForm.Get("pass") != "s3cret" {
			http.Error(w, "bad creds", http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", Path: "/"})
		writeString(t, w, "Welcome alice")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestFormLogin_Do_CapturesSessionAndCSRF(t *testing.T) {
	srv := loginServer(t)
	f := FormLogin{
		LoginURL:      srv.URL + "/login",
		UsernameField: "user",
		PasswordField: "pass",
		Username:      "alice",
		Password:      "s3cret",
		Success:       "Welcome",
	}
	res, err := f.Do(context.Background(), srv.Client())
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !strings.Contains(res.Cookies, "session=ok") {
		t.Errorf("cookies = %q, want session=ok", res.Cookies)
	}
}

func TestFormLogin_Do_AutoDetectsFields(t *testing.T) {
	srv := loginServer(t)
	// No field names given: must auto-detect user (text) and pass (password).
	f := FormLogin{
		LoginURL: srv.URL + "/login",
		Username: "alice",
		Password: "s3cret",
		Success:  "Welcome",
	}
	res, err := f.Do(context.Background(), srv.Client())
	if err != nil {
		t.Fatalf("Do with auto-detect: %v", err)
	}
	if !strings.Contains(res.Cookies, "session=ok") {
		t.Errorf("cookies = %q", res.Cookies)
	}
}

func TestFormLogin_Do_SuccessMarkerMismatch(t *testing.T) {
	srv := loginServer(t)
	f := FormLogin{
		LoginURL:      srv.URL + "/login",
		UsernameField: "user",
		PasswordField: "pass",
		Username:      "alice",
		Password:      "wrong-password",
		Success:       "Welcome",
	}
	if _, err := f.Do(context.Background(), srv.Client()); err == nil {
		t.Error("expected error when credentials are wrong / marker missing")
	}
}

func TestFormLogin_Do_Validation(t *testing.T) {
	cases := []FormLogin{
		{Username: "a", Password: "b"},              // no LoginURL
		{LoginURL: "http://x/login", Password: "b"}, // no username
		{LoginURL: "http://x/login", Username: "a"}, // no password
	}
	for i, c := range cases {
		if _, err := c.Do(context.Background(), nil); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
}

func TestParseLoginForm(t *testing.T) {
	base := mustURL(t, "https://example.com/auth/login")
	body := `<html><body>
<form action="../do-login" method="POST">
<input type="hidden" name="csrf" value="abc">
<input type="email" name="email">
<input type="password" name="pw">
</form></body></html>`
	form, err := parseLoginForm(body, base)
	if err != nil {
		t.Fatalf("parseLoginForm: %v", err)
	}
	if form.Action != "https://example.com/do-login" {
		t.Errorf("action = %q, want resolved https://example.com/do-login", form.Action)
	}
	if form.Method != "POST" {
		t.Errorf("method = %q, want POST", form.Method)
	}
	if form.Fields["csrf"] != "abc" {
		t.Errorf("hidden csrf = %q, want abc", form.Fields["csrf"])
	}
	if form.UserField != "email" {
		t.Errorf("UserField = %q, want email", form.UserField)
	}
	if form.PassField != "pw" {
		t.Errorf("PassField = %q, want pw", form.PassField)
	}
}

func TestParseLoginForm_PrefersPasswordForm(t *testing.T) {
	base := mustURL(t, "https://example.com/")
	body := `<html><body>
<form action="/search"><input type="text" name="q"></form>
<form action="/login" method="post"><input type="text" name="u"><input type="password" name="p"></form>
</body></html>`
	form, err := parseLoginForm(body, base)
	if err != nil {
		t.Fatalf("parseLoginForm: %v", err)
	}
	if !strings.HasSuffix(form.Action, "/login") {
		t.Errorf("action = %q, want the login form (has password)", form.Action)
	}
}

package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMergeCookies(t *testing.T) {
	cases := []struct{ a, b, want string }{
		{"", "", ""},
		{"x=1", "", "x=1"},
		{"", "y=2", "y=2"},
		{"x=1", "y=2", "x=1; y=2"},
	}
	for _, c := range cases {
		if got := mergeCookies(c.a, c.b); got != c.want {
			t.Errorf("mergeCookies(%q,%q) = %q, want %q", c.a, c.b, got, c.want)
		}
	}
}

func TestPerformLogin(t *testing.T) {
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, s string) {
		if _, err := w.Write([]byte(s)); err != nil {
			t.Errorf("write response: %v", err)
		}
	}
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			write(w, `<form action="/login" method="post"><input name="user" type="text"><input name="pass" type="password"></form>`)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("user") == "bob" && r.PostForm.Get("pass") == "pw" {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "42", Path: "/"})
			write(w, "OK logged in")
			return
		}
		http.Error(w, "no", http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Save/restore the globals performLogin reads.
	save := []string{loginURL, loginUser, loginPass, loginUserField, loginPassField, loginSuccess}
	t.Cleanup(func() {
		loginURL, loginUser, loginPass = save[0], save[1], save[2]
		loginUserField, loginPassField, loginSuccess = save[3], save[4], save[5]
	})

	loginURL = srv.URL + "/login"
	loginUser, loginPass = "bob", "pw"
	loginUserField, loginPassField = "user", "pass"
	loginSuccess = "logged in"

	got, err := performLogin(context.Background())
	if err != nil {
		t.Fatalf("performLogin: %v", err)
	}
	if !strings.Contains(got, "sid=42") {
		t.Errorf("cookies = %q, want sid=42", got)
	}
}

func TestPerformLogin_DisabledWhenNoURL(t *testing.T) {
	save := loginURL
	t.Cleanup(func() { loginURL = save })
	loginURL = ""
	got, err := performLogin(context.Background())
	if err != nil || got != "" {
		t.Errorf("performLogin disabled = (%q,%v), want (\"\",nil)", got, err)
	}
}

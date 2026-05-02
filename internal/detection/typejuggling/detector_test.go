package typejuggling

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// vulnerableLogin simulates a PHP server that uses `==` to compare a
// `0e`-prefixed stored hash to the supplied password. Any magic-hash
// value succeeds; everything else returns a generic error page.
func vulnerableLogin() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)
		// Form / JSON: extract password value via crude scan.
		pwd := ""
		for _, kv := range strings.Split(body, "&") {
			if strings.HasPrefix(kv, "password=") {
				pwd = kv[len("password="):]
			}
		}
		if pwd == "" {
			// JSON fallback.
			if i := strings.Index(body, `"password":"`); i >= 0 {
				rest := body[i+len(`"password":"`):]
				if j := strings.Index(rest, `"`); j >= 0 {
					pwd = rest[:j]
				}
			}
		}
		// Array-coerced password arrives as `password[]=x`.
		if strings.Contains(body, "password%5B%5D=") || strings.Contains(body, "password[]=") {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "abcdef"})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true,"token":"jwt-here","welcome":"alice"}`))
			return
		}
		if pwd == "0e1" || pwd == "0" || strings.HasPrefix(pwd, "0e") {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "abcdef"})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true,"token":"jwt-here","welcome":"alice"}`))
			return
		}
		// Random / wrong password — generic error.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body><h1>Login failed</h1><p>Invalid credentials.</p></body></html>`))
	}))
}

// strictLogin always returns the same generic error regardless of body.
func strictLogin() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid"}`))
	}))
}

func TestDetect_FlagsArrayCoercedPassword(t *testing.T) {
	srv := vulnerableLogin()
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/login", "admin")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected type-juggling finding")
	}
}

func TestDetect_NoFindingOnStrictLogin(t *testing.T) {
	srv := strictLogin()
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, _ := det.Detect(context.Background(), srv.URL+"/login", "admin")
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on strict login, got %d", len(res.Findings))
	}
}

func TestDetect_SkipsNonLoginPath(t *testing.T) {
	srv := vulnerableLogin()
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, _ := det.Detect(context.Background(), srv.URL+"/api/users", "admin")
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on non-login path, got %d", len(res.Findings))
	}
}

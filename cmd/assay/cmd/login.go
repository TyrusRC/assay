package cmd

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"time"

	"github.com/TyrusRC/assay/internal/auth"
)

// performLogin runs a scripted form login when --login-url is set and returns
// the captured session cookies, honoring --proxy and --insecure. It returns an
// empty string (no error) when login is not configured.
func performLogin(ctx context.Context) (string, error) {
	if loginURL == "" {
		return "", nil
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: loginTransport(),
	}
	f := auth.FormLogin{
		LoginURL:      loginURL,
		UsernameField: loginUserField,
		PasswordField: loginPassField,
		Username:      loginUser,
		Password:      loginPass,
		Success:       loginSuccess,
	}
	res, err := f.Do(ctx, client)
	if err != nil {
		return "", err
	}
	return res.Cookies, nil
}

// loginTransport builds an HTTP transport honoring the global --proxy and
// --insecure flags. InsecureSkipVerify is bound to the insecure variable
// (operator opt-in), never a literal true.
func loginTransport() *http.Transport {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec // operator opt-in via --insecure
	}
	if proxy != "" {
		if pu, err := url.Parse(proxy); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	return tr
}

// mergeCookies joins two Cookie header values, skipping empties.
func mergeCookies(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "; " + b
	}
}

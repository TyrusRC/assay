package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/TyrusRC/assay/internal/auth"
	"github.com/TyrusRC/assay/internal/headless"
)

// performLogin runs a login when --login-url is set and returns the captured
// session cookies. By default it uses a scripted HTTP form login; with
// --login-headless it drives a real browser (for SPA/JS logins). It returns an
// empty string (no error) when login is not configured.
func performLogin(ctx context.Context) (string, error) {
	if loginURL == "" {
		return "", nil
	}
	if loginHeadless {
		return performHeadlessLogin(ctx)
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

// performHeadlessLogin drives a JavaScript login in a real browser and returns
// the captured session cookies. --login-user-field / --login-pass-field are
// reused as optional CSS selectors for the credential inputs.
func performHeadlessLogin(ctx context.Context) (string, error) {
	pool, err := headless.NewPool(headless.PoolConfig{
		MaxBrowsers:     1,
		NavigateTimeout: 30 * time.Second,
		ExecPath:        chromePath,
		Headless:        true,
	})
	if err != nil {
		return "", fmt.Errorf("headless login needs a browser: %w", err)
	}
	defer pool.Close()

	page, err := pool.Acquire(ctx)
	if err != nil {
		return "", fmt.Errorf("acquire browser page: %w", err)
	}
	defer pool.Release(page)

	h := auth.HeadlessLogin{
		LoginURL:     loginURL,
		Username:     loginUser,
		Password:     loginPass,
		UserSelector: loginUserField,
		PassSelector: loginPassField,
		Success:      loginSuccess,
	}
	res, err := h.Do(ctx, page)
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

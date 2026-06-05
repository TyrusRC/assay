// Package auth performs scripted authentication so the scanner can test
// the content that lives behind a login. It currently supports classic
// HTML form logins over HTTP, capturing the resulting session cookies.
package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
)

// FormLogin describes a classic HTML form-based login.
type FormLogin struct {
	// LoginURL is the page hosting the login form.
	LoginURL string
	// UsernameField / PasswordField are the form field names. When empty,
	// "username"/"password" are assumed, with the password field also
	// auto-detected from an input[type=password].
	UsernameField string
	PasswordField string
	// Username / Password are the credentials to submit.
	Username string
	Password string
	// Extra carries additional form fields to submit (e.g. a tenant id).
	Extra map[string]string
	// Success, when set, must appear in the post-login response body for
	// the login to be considered successful.
	Success string
}

// Result holds the captured authenticated session.
type Result struct {
	// Cookies is a Cookie header value for the login origin, e.g.
	// "session=abc; csrf=xyz", suitable for scanner.AuthState.Cookies.
	Cookies string
}

// loginForm is the parsed shape of an HTML login form.
type loginForm struct {
	Action    string
	Method    string
	Fields    map[string]string
	UserField string
	PassField string
}

// Do performs the form login using client and returns the captured session.
// A cookie jar is attached to the client when one is not already present so
// Set-Cookie values issued during login are retained.
func (f FormLogin) Do(ctx context.Context, client *http.Client) (*Result, error) {
	if f.LoginURL == "" {
		return nil, fmt.Errorf("auth: login URL is required")
	}
	if f.Username == "" || f.Password == "" {
		return nil, fmt.Errorf("auth: username and password are required")
	}
	if client == nil {
		client = &http.Client{}
	}
	if client.Jar == nil {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, fmt.Errorf("auth: cookie jar: %w", err)
		}
		client.Jar = jar
	}

	base, err := url.Parse(f.LoginURL)
	if err != nil {
		return nil, fmt.Errorf("auth: parse login URL: %w", err)
	}

	form, err := f.fetchForm(ctx, client, base)
	if err != nil {
		return nil, err
	}

	values := f.buildValues(form)
	body, err := f.submit(ctx, client, form, values)
	if err != nil {
		return nil, err
	}
	if f.Success != "" && !strings.Contains(body, f.Success) {
		return nil, fmt.Errorf("auth: login did not succeed (success marker %q not found)", f.Success)
	}

	actionURL, perr := url.Parse(form.Action)
	if perr != nil {
		actionURL = base
	}
	cookies := cookiesToHeader(client.Jar, actionURL)
	if cookies == "" {
		return nil, fmt.Errorf("auth: login produced no session cookies")
	}
	return &Result{Cookies: cookies}, nil
}

// fetchForm GETs the login page and parses its login form. If no form is
// found the login URL itself is used as a POST target with default fields.
func (f FormLogin) fetchForm(ctx context.Context, client *http.Client, base *url.URL) (*loginForm, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.LoginURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("auth: build login GET: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: GET login page: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return nil, fmt.Errorf("auth: read login page: %w", err)
	}

	form, err := parseLoginForm(string(data), base)
	if err != nil {
		// No parseable form: fall back to posting directly to the login URL.
		return &loginForm{Action: f.LoginURL, Method: http.MethodPost, Fields: map[string]string{}}, nil
	}
	return form, nil
}

// buildValues merges the form's pre-filled fields with the configured
// credentials and extra fields.
func (f FormLogin) buildValues(form *loginForm) url.Values {
	userField := f.UsernameField
	if userField == "" {
		userField = form.UserField
	}
	if userField == "" {
		userField = "username"
	}
	passField := f.PasswordField
	if passField == "" {
		passField = form.PassField
	}
	if passField == "" {
		passField = "password"
	}

	values := url.Values{}
	for k, v := range form.Fields {
		values.Set(k, v)
	}
	values.Set(userField, f.Username)
	values.Set(passField, f.Password)
	for k, v := range f.Extra {
		values.Set(k, v)
	}
	return values
}

// submit POSTs (or GETs) the form values and returns the response body.
func (f FormLogin) submit(ctx context.Context, client *http.Client, form *loginForm, values url.Values) (string, error) {
	method := strings.ToUpper(form.Method)
	if method == "" {
		method = http.MethodPost
	}
	req, err := buildLoginRequest(ctx, method, form.Action, values)
	if err != nil {
		return "", fmt.Errorf("auth: build login request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth: submit login: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return "", fmt.Errorf("auth: read login response: %w", err)
	}
	return string(data), nil
}

// buildLoginRequest constructs the login submission request. GET encodes the
// values into the query string; other methods send a urlencoded body.
func buildLoginRequest(ctx context.Context, method, action string, values url.Values) (*http.Request, error) {
	if method == http.MethodGet {
		return http.NewRequestWithContext(ctx, http.MethodGet, appendQuery(action, values.Encode()), http.NoBody)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, action, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

// appendQuery appends an encoded query string to u, choosing ? or & correctly.
func appendQuery(u, encoded string) string {
	if strings.Contains(u, "?") {
		return u + "&" + encoded
	}
	return u + "?" + encoded
}

// cookiesToHeader renders the jar's cookies for u as a Cookie header value.
func cookiesToHeader(jar http.CookieJar, u *url.URL) string {
	if jar == nil || u == nil {
		return ""
	}
	cookies := jar.Cookies(u)
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

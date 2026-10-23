package session

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// LoginSequence is a recorded login flow that assay replays to acquire
// an authenticated session. The JSON format mirrors the Acunetix LSR
// schema (navigate/change/click/submit actions, a detection rule to
// verify the session is alive, and a restriction list of URLs the
// crawler must never replay).
type LoginSequence struct {
	Actions      []Action  `json:"actions"`
	Detection    Detection `json:"detection"`
	Restrictions []string  `json:"restrictions"`
}

// Action is one step in the login flow.
type Action struct {
	Type   string `json:"type"`   // navigate, type, click, submit, wait, script
	Target string `json:"target"` // URL (navigate) or CSS selector (type/click)
	Value  string `json:"value,omitempty"`
}

// Detection defines how to verify the session is still alive.
type Detection struct {
	Type  string `json:"type"`  // status_is, status_is_not, in_body, not_in_body, in_headers, not_in_headers
	Value string `json:"value"` // expected value to match
	URL   string `json:"url"`   // validation URL to poll periodically
}

// LoadLSR reads a login-sequence JSON file from disk.
func LoadLSR(path string) (*LoginSequence, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("lsr: open %s: %w", path, err)
	}
	defer f.Close()

	var lsr LoginSequence
	if err := json.NewDecoder(f).Decode(&lsr); err != nil {
		return nil, fmt.Errorf("lsr: decode %s: %w", path, err)
	}
	if len(lsr.Actions) == 0 {
		return nil, fmt.Errorf("lsr: %s contains no actions", path)
	}
	return &lsr, nil
}

// ReplayLSR replays the login sequence using plain HTTP requests and
// returns the cookies acquired. Headless-only actions (click on a CSS
// selector, type into a JS-rendered input) are skipped with a warning
// — pass headless=true when a browser pool is wired in. This
// implementation handles navigate and submit (form POST) actions.
func ReplayLSR(ctx context.Context, lsr *LoginSequence) (cookies string, err error) {
	jar := map[string]string{} // simple name→value cookie jar
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	for i, action := range lsr.Actions {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		switch action.Type {
		case "navigate":
			resp, gerr := doGet(ctx, client, action.Target, jar)
			if gerr != nil {
				return "", fmt.Errorf("lsr action %d (navigate %s): %w", i, action.Target, gerr)
			}
			collectCookies(resp, jar)

		case "submit":
			form := url.Values{}
			if action.Value != "" {
				for _, pair := range strings.Split(action.Value, "&") {
					kv := strings.SplitN(pair, "=", 2)
					if len(kv) == 2 {
						form.Set(kv[0], kv[1])
					}
				}
			}
			resp, perr := doPost(ctx, client, action.Target, form, jar)
			if perr != nil {
				return "", fmt.Errorf("lsr action %d (submit %s): %w", i, action.Target, perr)
			}
			collectCookies(resp, jar)

		case "wait":
			// Pause between actions.
			d, _ := time.ParseDuration(action.Value)
			if d == 0 {
				d = 500 * time.Millisecond
			}
			time.Sleep(d)

		case "click", "type", "script":
			// Headless-only — skip silently in HTTP-only mode.
			continue

		default:
			return "", fmt.Errorf("lsr action %d: unknown type %q", i, action.Type)
		}
	}

	// Build a cookie header from the jar.
	var parts []string
	for name, value := range jar {
		parts = append(parts, name+"="+value)
	}
	return strings.Join(parts, "; "), nil
}

// IsRestricted checks whether a URL is in the LSR's restriction list
// (logout, CSRF refresh, etc.). The scanner scope layer calls this to
// prevent the crawler from replaying session-destroying endpoints.
func (lsr *LoginSequence) IsRestricted(rawURL string) bool {
	for _, pattern := range lsr.Restrictions {
		if strings.Contains(rawURL, pattern) {
			return true
		}
	}
	return false
}

// CheckSession uses the detection rule to verify the session is still
// alive. Returns true if the session is valid, false if re-login is
// needed.
func (lsr *LoginSequence) CheckSession(ctx context.Context, cookies string) (bool, error) {
	if lsr.Detection.URL == "" {
		return true, nil // no detection rule — assume alive
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, lsr.Detection.URL, nil)
	if err != nil {
		return false, err
	}
	if cookies != "" {
		req.Header.Set("Cookie", cookies)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	switch lsr.Detection.Type {
	case "status_is":
		return fmt.Sprintf("%d", resp.StatusCode) == lsr.Detection.Value, nil
	case "status_is_not":
		return fmt.Sprintf("%d", resp.StatusCode) != lsr.Detection.Value, nil
	case "in_body":
		return strings.Contains(string(body), lsr.Detection.Value), nil
	case "not_in_body":
		return !strings.Contains(string(body), lsr.Detection.Value), nil
	case "in_headers":
		for _, vals := range resp.Header {
			for _, v := range vals {
				if strings.Contains(v, lsr.Detection.Value) {
					return true, nil
				}
			}
		}
		return false, nil
	case "not_in_headers":
		for _, vals := range resp.Header {
			for _, v := range vals {
				if strings.Contains(v, lsr.Detection.Value) {
					return false, nil
				}
			}
		}
		return true, nil
	default:
		return true, nil
	}
}

// ── helpers ──

func doGet(ctx context.Context, client *http.Client, rawURL string, jar map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	applyCookies(req, jar)
	return client.Do(req)
}

func doPost(ctx context.Context, client *http.Client, rawURL string, form url.Values, jar map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	applyCookies(req, jar)
	return client.Do(req)
}

func applyCookies(req *http.Request, jar map[string]string) {
	if len(jar) == 0 {
		return
	}
	var parts []string
	for k, v := range jar {
		parts = append(parts, k+"="+v)
	}
	req.Header.Set("Cookie", strings.Join(parts, "; "))
}

func collectCookies(resp *http.Response, jar map[string]string) {
	for _, c := range resp.Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(jar, c.Name)
		} else {
			jar[c.Name] = c.Value
		}
	}
}

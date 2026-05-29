// Package iistilde detects the IIS short-name (8.3 / "tilde") enumeration
// vulnerability — IIS leaks the existence of files and directories whose
// 8.3 short-name prefix matches a wildcard pattern, allowing an attacker
// to enumerate names a directory listing would never reveal.
//
// The differential: IIS distinguishes "path matched, but cannot serve"
// (response code A) from "path did not match" (response code B). The two
// codes vary by IIS version and method (GET 200/404, OPTIONS 200/400,
// DEBUG/TRACK on older builds), but the *difference* is the tell.
//
// Mirrors AWVS IIS_Tilde_Dir_Enumeration.script.
//
// References:
//   - Soroush Dalili, "IIS Short File / Folder Name Disclosure" (2010,
//     re-confirmed for IIS 7.5–10 with kernel-mode handler).
//   - HackTricks IIS chapter.
package iistilde

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Probe is one tilde-enumeration request signature.
type Probe struct {
	Path        string
	Method      string
	Description string
}

// Result reports the outcome of a Detect run.
type Result struct {
	Vulnerable bool
	Method     string
	Evidence   string
	Probes     int
}

// Probes returns the canonical probe set. Each path embeds a `~1`
// wildcard suffix designed to match any-or-no short name.
func Probes() []Probe {
	return []Probe{
		{Path: "/a~1*/.aspx", Method: http.MethodGet, Description: "GET 'a~1*' wildcard short-name probe"},
		{Path: "/A~1.*/.aspx", Method: http.MethodGet, Description: "GET uppercase short-name probe"},
		{Path: "/*~1*/", Method: http.MethodOptions, Description: "OPTIONS wildcard short-name probe"},
		{Path: "/a~1.*/", Method: "DEBUG", Description: "DEBUG verb tilde probe (older IIS)"},
		{Path: "/a~1.*/", Method: "TRACK", Description: "TRACK verb tilde probe (older IIS)"},
	}
}

// Detect runs the probe set against base and reports whether responses
// differ between matching and non-matching paths in a way that indicates
// the tilde-enumeration vulnerability. The control probe is a path
// guaranteed not to match (sufficiently random base + `~1`).
func Detect(base string, client *http.Client) (Result, error) {
	if _, err := url.Parse(base); err != nil || !strings.Contains(base, "://") {
		return Result{}, fmt.Errorf("iistilde: invalid base URL %q", base)
	}
	if client == nil {
		client = http.DefaultClient
	}

	control, err := requestStatus(client, http.MethodGet, base+"/qz9q9q~1*/.aspx")
	if err != nil {
		return Result{}, fmt.Errorf("iistilde: control probe failed: %w", err)
	}

	probes := Probes()
	for _, p := range probes {
		code, err := requestStatus(client, p.Method, base+p.Path)
		if err != nil {
			// Network glitch on this probe — skip rather than abort
			// the whole detector.
			continue
		}
		if code != 0 && code != control {
			return Result{
				Vulnerable: true,
				Method:     p.Method,
				Evidence:   fmt.Sprintf("control=%d, probe %s %s=%d", control, p.Method, p.Path, code),
				Probes:     len(probes),
			}, nil
		}
	}
	return Result{Vulnerable: false, Probes: len(probes)}, nil
}

func requestStatus(client *http.Client, method, target string) (int, error) {
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

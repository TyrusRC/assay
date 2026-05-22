package authbypass403

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	scanhttp "github.com/TyrusRC/assay/internal/http"
)

// Detector probes for 401/403 access-control bypass via well-known
// proxy-trust headers and path-parameter / path-encoding tricks that
// reverse proxies and frameworks parse differently.
type Detector struct {
	client  *scanhttp.Client
	verbose bool
}

// New constructs a Detector.
func New(client *scanhttp.Client) *Detector {
	return &Detector{client: client}
}

// WithVerbose toggles diagnostic output.
func (d *Detector) WithVerbose(v bool) *Detector {
	d.verbose = v
	return d
}

// Name returns the detector identifier.
func (d *Detector) Name() string { return "authbypass403" }

// Description returns a one-line summary.
func (d *Detector) Description() string {
	return "Probes for 401/403 access-control bypass via reverse-proxy trust headers (X-Original-URL, X-Rewrite-URL, X-Forwarded-For, X-Custom-IP-Authorization) and path-encoding tricks (;jsessionid=, /..;/, %2e%2e) that frontend ACLs and backend routers parse differently."
}

// DetectOptions configures the probe.
type DetectOptions struct {
	Timeout time.Duration
}

// DefaultOptions returns recommended defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{Timeout: 10 * time.Second}
}

// DetectionResult carries findings and the list of techniques that
// triggered.
type DetectionResult struct {
	Vulnerable bool
	Findings   []*core.Finding
	Techniques []string
}

type variant struct {
	technique string
	// mutate returns the request that exercises this variant. nil
	// indicates "use baseline URL with these extra headers".
	headers map[string]string
	// pathReplace, if set, overrides target.Path with a mutated form.
	pathReplace func(original string) string
}

// Detect runs the probe set. It bails when the baseline isn't a 401
// or 403 (otherwise there's nothing to bypass).
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	res := &DetectionResult{
		Findings:   make([]*core.Finding, 0),
		Techniques: make([]string, 0),
	}
	if d == nil || d.client == nil {
		return res, nil
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultOptions().Timeout
	}

	u, err := url.Parse(target)
	if err != nil {
		return res, fmt.Errorf("authbypass403: parse: %w", err)
	}

	baseline, err := d.do(ctx, u.String(), nil, opts.Timeout)
	if err != nil || baseline == nil {
		return res, nil
	}
	if baseline.StatusCode != 401 && baseline.StatusCode != 403 {
		return res, nil
	}

	for _, v := range variants(u) {
		var probeURL string
		if v.pathReplace != nil {
			mutated := *u
			mutated.Path = v.pathReplace(u.Path)
			mutated.RawPath = ""
			probeURL = mutated.String()
		} else {
			probeURL = u.String()
		}
		probe, err := d.do(ctx, probeURL, v.headers, opts.Timeout)
		if err != nil || probe == nil {
			continue
		}
		if bypassed(baseline, probe) {
			res.Techniques = append(res.Techniques, v.technique)
			res.Findings = append(res.Findings, buildFinding(v.technique, target))
		}
	}

	res.Vulnerable = len(res.Findings) > 0
	return res, nil
}

// bypassed reports whether the probe response indicates the access
// control was circumvented relative to the baseline.
func bypassed(baseline, probe *scanhttp.Response) bool {
	// Clear win: the probe came back 2xx where the baseline was 4xx.
	if probe.StatusCode >= 200 && probe.StatusCode < 300 {
		return true
	}
	// Some setups return 30x to a logged-in page (different from the
	// baseline's login redirect). Match only when the status family
	// genuinely changed and the body differs.
	if probe.StatusCode/100 != baseline.StatusCode/100 &&
		probe.Body != baseline.Body {
		return true
	}
	return false
}

// variants returns the ordered set of probes for target u. Path-based
// probes are skipped when the target has no path beyond '/'.
func variants(u *url.URL) []variant {
	pathFor := func() string {
		if u.Path == "" {
			return "/"
		}
		return u.Path
	}
	out := []variant{
		{
			technique: "header_x_original_url",
			headers:   map[string]string{"X-Original-URL": pathFor()},
		},
		{
			technique: "header_x_rewrite_url",
			headers:   map[string]string{"X-Rewrite-URL": pathFor()},
		},
		{
			technique: "header_forwarded_for_loopback",
			headers:   map[string]string{"X-Forwarded-For": "127.0.0.1"},
		},
		{
			technique: "header_custom_ip_authorization",
			headers:   map[string]string{"X-Custom-IP-Authorization": "127.0.0.1"},
		},
		{
			technique: "header_forwarded_host_localhost",
			headers:   map[string]string{"X-Forwarded-Host": "localhost"},
		},
	}
	if u.Path != "" && u.Path != "/" {
		out = append(out,
			variant{
				technique: "path_semicolon_truncation",
				pathReplace: func(p string) string {
					return p + ";foo=bar"
				},
			},
			variant{
				technique: "path_trailing_slash_flip",
				pathReplace: func(p string) string {
					if strings.HasSuffix(p, "/") {
						return strings.TrimRight(p, "/")
					}
					return p + "/"
				},
			},
			variant{
				technique: "path_dotseg_traversal",
				pathReplace: func(p string) string {
					// /..;/<original> — Tomcat treats /..; as a
					// path-parameter on .. and routes to <original>
					return "/..;" + p
				},
			},
		)
	}
	return out
}

func (d *Detector) do(ctx context.Context, target string, headers map[string]string, timeout time.Duration) (*scanhttp.Response, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return d.client.Do(reqCtx, &scanhttp.Request{
		Method:  "GET",
		URL:     target,
		Headers: headers,
	})
}

func buildFinding(technique, target string) *core.Finding {
	titles := map[string]string{
		"header_x_original_url":           "Access control bypass — X-Original-URL header trusted by upstream router",
		"header_x_rewrite_url":            "Access control bypass — X-Rewrite-URL header trusted by upstream router",
		"header_forwarded_for_loopback":   "Access control bypass — X-Forwarded-For: 127.0.0.1 grants internal trust",
		"header_custom_ip_authorization":  "Access control bypass — X-Custom-IP-Authorization grants internal trust",
		"header_forwarded_host_localhost": "Access control bypass — X-Forwarded-Host: localhost grants internal trust",
		"path_semicolon_truncation":       "Access control bypass — path-parameter semicolon evades upstream ACL",
		"path_trailing_slash_flip":        "Access control bypass — trailing-slash mismatch evades upstream ACL",
		"path_dotseg_traversal":           "Access control bypass — /..; path-parameter normalization evades upstream ACL",
	}
	descs := map[string]string{
		"header_x_original_url":           "The application routed to the protected path because it trusted the X-Original-URL header value over the literal request line. The front-end ACL inspected the literal URL (rejected with 403) but the upstream framework re-dispatched on the header. Any client can reach the protected resource by setting this header.",
		"header_x_rewrite_url":            "Same trust-the-header-over-the-URL pattern, exposed via X-Rewrite-URL (commonly enabled on classic IIS and Symfony stacks). An anonymous client reaches the protected resource by setting the header.",
		"header_forwarded_for_loopback":   "The application granted internal/admin privileges when X-Forwarded-For contained 127.0.0.1. The header is client-controlled in any reachable deployment; this is an unauthenticated privilege grant.",
		"header_custom_ip_authorization":  "The application granted privileges based on a client-supplied IP header. Any client can claim to be on the internal network by setting the header — no further proof required.",
		"header_forwarded_host_localhost": "The application granted privileges based on X-Forwarded-Host claiming localhost. Same client-controlled-header anti-pattern as X-Forwarded-For.",
		"path_semicolon_truncation":       "The reverse proxy / front-end ACL checked the literal path (rejected with 403) but the upstream framework stripped the ;foo=bar path-parameter and routed to the unprotected base path. Tomcat, JBoss, and several Spring stacks default to this behavior.",
		"path_trailing_slash_flip":        "Adding or removing a trailing slash flipped the 403 to a successful response — the ACL and the router disagree on path canonicalization, leaving the resource reachable.",
		"path_dotseg_traversal":           "The /..;/<path> form bypassed the ACL: the upstream framework normalized /..; as a path-parameter on '..' and routed to <path>, while the ACL checked the literal request line. This is the classic Tomcat dotsegment trick.",
	}
	severity := core.SeverityHigh
	f := core.NewFinding("Access control bypass", severity)
	f.Title = titles[technique]
	f.URL = target
	f.Tool = "authbypass403-detector"
	f.Description = descs[technique]
	f.Evidence = "baseline returned 401/403; " + technique + " probe returned a successful (2xx) or distinct authenticated-looking response"
	f.Remediation = "Decide access in one place — preferably the upstream framework — and treat all hop-by-hop and X-* headers as untrusted on the public edge. Reject requests carrying these headers at the edge, or strip them before they reach the backend. Align URL canonicalization (semicolons, dotsegments, encoded slashes, trailing slashes) between the ACL and the router."
	f.WithOWASPMapping(
		[]string{"WSTG-ATHZ-01", "WSTG-ATHZ-02"},
		[]string{"A01:2025"},
		[]string{"CWE-285", "CWE-287"},
	)
	return f
}

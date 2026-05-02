package storage

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
)

// sessionCookiePatterns contains substrings that indicate a session-related cookie.
var sessionCookiePatterns = []string{
	"session",
	"sess",
	"sid",
	"token",
	"auth",
	"jsessionid",
	"phpsessid",
	"asp.net_sessionid",
	"connect.sid",
}

// minSessionIDLength is the minimum acceptable length for a session ID value.
const minSessionIDLength = 16

// minSessionEntropy is the minimum acceptable Shannon entropy per character.
const minSessionEntropy = 3.0

// Detector checks cookies and session management for security weaknesses.
type Detector struct {
	client  *http.Client
	verbose bool
}

// DetectOptions configures which checks the detector performs.
type DetectOptions struct {
	// Timeout sets the HTTP request timeout.
	Timeout time.Duration
	// CheckCookieFlags enables checking for Secure, HttpOnly, SameSite, and Domain attributes.
	CheckCookieFlags bool
	// CheckSessionMgmt enables session entropy and fixation checks.
	CheckSessionMgmt bool
}

// DetectionResult holds the outcome of a storage security scan.
type DetectionResult struct {
	// Vulnerable is true when at least one finding was produced.
	Vulnerable bool
	// Findings contains the individual security issues discovered.
	Findings []*core.Finding
	// AnalyzedCookies is the number of Set-Cookie headers examined.
	AnalyzedCookies int
	// InsecureCookies lists the names of cookies that had at least one issue.
	InsecureCookies []string
}

// New creates a new storage Detector backed by the given HTTP client.
func New(client *http.Client) *Detector {
	return &Detector{
		client: client,
	}
}

// WithVerbose enables verbose output.
func (d *Detector) WithVerbose(verbose bool) *Detector {
	d.verbose = verbose
	return d
}

// Name returns the detector name.
func (d *Detector) Name() string {
	return "storage"
}

// Description returns a human-readable description of this detector.
func (d *Detector) Description() string {
	return "Cookie and session management vulnerability detector " +
		"(Secure, HttpOnly, SameSite, Domain, session entropy, session fixation)"
}

// DefaultOptions returns the recommended default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		Timeout:          10 * time.Second,
		CheckCookieFlags: true,
		CheckSessionMgmt: true,
	}
}

// Detect performs cookie and session analysis against the target URL.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		Findings:        make([]*core.Finding, 0),
		InsecureCookies: make([]string, 0),
	}

	// Build the initial GET request.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request target: %w", err)
	}
	defer resp.Body.Close()

	cookies := resp.Cookies()
	result.AnalyzedCookies = len(cookies)

	if len(cookies) == 0 {
		return result, nil
	}

	// Track which cookies are insecure so we can deduplicate the list.
	insecureSet := make(map[string]bool)

	// --- Cookie flag analysis ---
	if opts.CheckCookieFlags {
		for _, c := range cookies {
			issues := d.analyzeCookieFlags(target, c)
			if len(issues) > 0 {
				insecureSet[c.Name] = true
				result.Findings = append(result.Findings, issues...)
			}
		}
	}

	// --- Session management analysis ---
	if opts.CheckSessionMgmt {
		for _, c := range cookies {
			if !isSessionCookieName(c.Name) {
				continue
			}

			// Check session ID entropy.
			if isLowEntropy(c.Value) {
				finding := d.createFinding(
					target,
					c.Name,
					core.SeverityMedium,
					fmt.Sprintf("Session cookie '%s' has a low-entropy or predictable value (length=%d)",
						c.Name, len(c.Value)),
					fmt.Sprintf("Cookie value: %s", c.Value),
					"low-entropy-session",
				)
				finding.WithOWASPMapping(
					[]string{"WSTG-SESS-01"},
					[]string{"A07:2025"},
					[]string{"CWE-330"},
				)
				result.Findings = append(result.Findings, finding)
				insecureSet[c.Name] = true
			}

			// Check session fixation.
			fixated, fixErr := d.checkSessionFixation(ctx, target, c.Name)
			if fixErr == nil && fixated {
				finding := d.createFinding(
					target,
					c.Name,
					core.SeverityHigh,
					fmt.Sprintf("Session cookie '%s' is vulnerable to session fixation "+
						"(server accepted externally-set session ID without regenerating)", c.Name),
					fmt.Sprintf("Sent Cookie: %s=attacker-controlled-fixation-test; "+
						"server echoed same value back", c.Name),
					"session-fixation",
				)
				finding.WithOWASPMapping(
					[]string{"WSTG-SESS-03"},
					[]string{"A07:2025"},
					[]string{"CWE-384"},
				)
				result.Findings = append(result.Findings, finding)
				insecureSet[c.Name] = true
			}
		}
	}

	// Build the insecure cookies list.
	for name := range insecureSet {
		result.InsecureCookies = append(result.InsecureCookies, name)
	}

	result.Vulnerable = len(result.Findings) > 0
	return result, nil
}

// analyzeCookieFlags returns findings for missing security attributes on a cookie.
func (d *Detector) analyzeCookieFlags(target string, c *http.Cookie) []*core.Finding {
	var findings []*core.Finding

	// Missing Secure flag (CWE-614).
	if !c.Secure {
		f := d.createFinding(
			target,
			c.Name,
			core.SeverityMedium,
			fmt.Sprintf("Cookie '%s' is missing the Secure flag; it may be transmitted over unencrypted HTTP", c.Name),
			fmt.Sprintf("Set-Cookie: %s=<value>; (no Secure flag)", c.Name),
			"missing-secure",
		)
		f.WithOWASPMapping(
			[]string{"WSTG-SESS-02"},
			[]string{"A05:2025"},
			[]string{"CWE-614"},
		)
		findings = append(findings, f)
	}

	// Missing HttpOnly flag (CWE-1004).
	if !c.HttpOnly {
		f := d.createFinding(
			target,
			c.Name,
			core.SeverityMedium,
			fmt.Sprintf("Cookie '%s' is missing the HttpOnly flag; it is accessible to client-side scripts", c.Name),
			fmt.Sprintf("Set-Cookie: %s=<value>; (no HttpOnly flag)", c.Name),
			"missing-httponly",
		)
		f.WithOWASPMapping(
			[]string{"WSTG-SESS-02"},
			[]string{"A05:2025"},
			[]string{"CWE-1004"},
		)
		findings = append(findings, f)
	}

	// Missing or weak SameSite attribute (CWE-16).
	if c.SameSite == http.SameSiteDefaultMode || c.SameSite == 0 {
		f := d.createFinding(
			target,
			c.Name,
			core.SeverityLow,
			fmt.Sprintf("Cookie '%s' is missing the SameSite attribute; it may be sent in cross-site requests", c.Name),
			fmt.Sprintf("Set-Cookie: %s=<value>; (no SameSite attribute)", c.Name),
			"missing-samesite",
		)
		f.WithOWASPMapping(
			[]string{"WSTG-SESS-02"},
			[]string{"A05:2025"},
			[]string{"CWE-16"},
		)
		findings = append(findings, f)
	} else if c.SameSite == http.SameSiteNoneMode {
		f := d.createFinding(
			target,
			c.Name,
			core.SeverityLow,
			fmt.Sprintf("Cookie '%s' uses SameSite=None which allows cross-site transmission", c.Name),
			fmt.Sprintf("Set-Cookie: %s=<value>; SameSite=None", c.Name),
			"weak-samesite",
		)
		f.WithOWASPMapping(
			[]string{"WSTG-SESS-02"},
			[]string{"A05:2025"},
			[]string{"CWE-16"},
		)
		findings = append(findings, f)
	}

	// Overly broad Domain attribute (CWE-16).
	// Per RFC 6265, any explicit Domain attribute causes the cookie to be
	// shared with all subdomains. Go's http.Cookie parser strips the leading
	// dot, so we check for a non-empty Domain value.
	if c.Domain != "" {
		f := d.createFinding(
			target,
			c.Name,
			core.SeverityLow,
			fmt.Sprintf("Cookie '%s' has an overly broad Domain attribute (%s); "+
				"it will be sent to all subdomains", c.Name, c.Domain),
			fmt.Sprintf("Set-Cookie: %s=<value>; Domain=%s", c.Name, c.Domain),
			"broad-domain",
		)
		f.WithOWASPMapping(
			[]string{"WSTG-SESS-02"},
			[]string{"A05:2025"},
			[]string{"CWE-16"},
		)
		findings = append(findings, f)
	}

	return findings
}

// checkSessionFixation sends a request with a pre-set session cookie and checks
// whether the server echoes the same value back without regenerating the ID.
func (d *Detector) checkSessionFixation(ctx context.Context, target, cookieName string) (bool, error) {
	const fixationTestValue = "attacker-controlled-fixation-test"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return false, fmt.Errorf("create fixation request: %w", err)
	}
	req.AddCookie(&http.Cookie{
		Name:  cookieName,
		Value: fixationTestValue,
	})

	resp, err := d.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("fixation request: %w", err)
	}
	defer resp.Body.Close()

	for _, c := range resp.Cookies() {
		if c.Name == cookieName && c.Value == fixationTestValue {
			return true, nil
		}
	}
	return false, nil
}

// createFinding builds a core.Finding with the standard fields populated.
func (d *Detector) createFinding(target, param string, sev core.Severity, desc, evidence, tool string) *core.Finding {
	f := core.NewFinding("Cookie/Session Misconfiguration", sev)
	f.URL = target
	f.Parameter = param
	f.Description = desc
	f.Evidence = evidence
	f.Tool = "storage-detector/" + tool
	f.Remediation = "Set Secure, HttpOnly, and SameSite=Strict on all session cookies. " +
		"Avoid overly broad Domain attributes. " +
		"Use high-entropy, cryptographically random session IDs (minimum 128 bits). " +
		"Regenerate session IDs after authentication to prevent session fixation."
	return f
}

// isSessionCookieName returns true when the cookie name matches common session-ID naming patterns.
func isSessionCookieName(name string) bool {
	lower := strings.ToLower(name)
	for _, pattern := range sessionCookiePatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// isLowEntropy returns true if the value is too short or has too little Shannon entropy.
func isLowEntropy(value string) bool {
	if len(value) < minSessionIDLength {
		return true
	}
	return calculateEntropy(value) < minSessionEntropy
}

// calculateEntropy returns the Shannon entropy per character of the given string.
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]float64, len(s))
	for _, r := range s {
		freq[r]++
	}

	total := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		p := count / total
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

package longpwd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

// Detector is the scanner-side wrapper. It POSTs two form submissions
// to a login URL — one with a normal-length password (baseline) and one
// with a 100k-character password — and reports a finding when the
// timing delta exceeds the noise floor.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New constructs a Detector.
func New(client *http.Client) *Detector {
	if client == nil {
		client = http.DefaultClient
	}
	return &Detector{client: client}
}

// WithVerbose toggles diagnostic output.
func (d *Detector) WithVerbose(v bool) *Detector {
	d.verbose = v
	return d
}

// DetectOptions tunes the probe.
type DetectOptions struct {
	Timeout       time.Duration
	UsernameField string // form field for the username. Default: "username".
	PasswordField string // form field for the password. Default: "password".
	Username      string // value to submit. Default: "assay-test-user".
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		Timeout:       30 * time.Second,
		UsernameField: "username",
		PasswordField: "password",
		Username:      "assay-test-user",
	}
}

// DetectionResult mirrors the scanner convention.
type DetectionResult struct {
	URL        string
	Analysis   Result
	Findings   []*core.Finding
	Vulnerable bool
}

// Detect submits two timed login attempts (baseline, then 100k-char
// password) and emits a finding when the delta is over the threshold.
func (d *Detector) Detect(ctx context.Context, loginURL string, opts DetectOptions) (*DetectionResult, error) {
	if opts.Timeout <= 0 {
		opts = DefaultOptions()
	}
	if opts.UsernameField == "" {
		opts.UsernameField = "username"
	}
	if opts.PasswordField == "" {
		opts.PasswordField = "password"
	}
	if opts.Username == "" {
		opts.Username = "assay-test-user"
	}

	pwds := GetPasswords()
	if len(pwds) == 0 {
		return nil, fmt.Errorf("longpwd: no probe passwords")
	}
	baseline, err := d.timePost(ctx, loginURL, opts, pwds[0])
	if err != nil {
		return nil, fmt.Errorf("longpwd: baseline probe: %w", err)
	}
	long, err := d.timePost(ctx, loginURL, opts, pwds[len(pwds)-1])
	if err != nil {
		return nil, fmt.Errorf("longpwd: long-password probe: %w", err)
	}

	analysis := Evaluate(baseline, long)
	result := &DetectionResult{URL: loginURL, Analysis: analysis, Vulnerable: analysis.Vulnerable}
	if analysis.Vulnerable {
		result.Findings = append(result.Findings, d.toFinding(loginURL, analysis, len(pwds[len(pwds)-1])))
	}
	return result, nil
}

func (d *Detector) timePost(ctx context.Context, target string, opts DetectOptions, password string) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	form := url.Values{}
	form.Set(opts.UsernameField, opts.Username)
	form.Set(opts.PasswordField, password)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	start := time.Now()
	resp, err := d.client.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return time.Since(start), nil
}

func (d *Detector) toFinding(target string, a Result, longLen int) *core.Finding {
	f := core.NewFinding("long_password_dos", core.SeverityMedium)
	f.Tool = "longpwd"
	f.URL = target
	f.Title = "Long-password denial-of-service in authentication endpoint"
	f.Confidence = core.ConfidenceMedium
	f.Description = fmt.Sprintf(
		"The login endpoint hashes the full submitted password without length-capping. "+
			"A %d-character probe took %v longer than a 10-char baseline, indicating the server forwards the entire string to bcrypt/Argon2/scrypt. "+
			"An attacker can burn one worker thread per request, achieving cheap DoS at low request rates.",
		longLen, a.Delta,
	)
	f.Evidence = fmt.Sprintf("delta=%v (threshold=%v); %s", a.Delta, VulnerabilityThreshold(), a.Notes)
	f.Metadata["delta_ms"] = a.Delta.Milliseconds()
	f.Metadata["probe_length"] = longLen
	f.Remediation = "Length-cap the password before hashing (Django uses 4096 bytes; OWASP recommends 64–128 for bcrypt due to its 72-byte truncation behaviour). " +
		"Reject the request with HTTP 413 above the cap; do not silently truncate."
	f.References = []string{
		"https://www.djangoproject.com/weblog/2013/sep/15/security/",
		"https://owasp.org/Top10/A04_2021-Insecure_Design/",
	}
	f = f.WithOWASPMapping(
		[]string{"WSTG-ATHN-09"},
		[]string{"A04:2021"},
		[]string{"CWE-770"},
	)
	return f
}

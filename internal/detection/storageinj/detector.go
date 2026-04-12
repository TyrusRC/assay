package storageinj

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/headless"
	"github.com/swiss-knife-for-web-security/skws/internal/payloads/storageinj"
)

// Detector tests for client-side storage injection vulnerabilities.
type Detector struct {
	pool    *headless.Pool
	verbose bool
}

// New creates a new storage injection Detector.
// If pool is nil, the detector gracefully skips all tests.
func New(pool *headless.Pool) *Detector {
	return &Detector{pool: pool}
}

// WithVerbose enables verbose output.
func (d *Detector) WithVerbose(verbose bool) *Detector {
	d.verbose = verbose
	return d
}

// DetectOptions configures detection behavior.
type DetectOptions struct {
	Timeout        time.Duration
	CheckSensitive bool // Check for sensitive data in storage
	MaxPayloads    int
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		Timeout:        30 * time.Second,
		CheckSensitive: true,
		MaxPayloads:    10,
	}
}

// DetectionResult contains the results of storage injection testing.
type DetectionResult struct {
	Vulnerable bool
	Findings   []*core.Finding
}

// Detect tests for storage injection vulnerabilities on the given URL.
func (d *Detector) Detect(ctx context.Context, targetURL string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{}

	if d.pool == nil {
		return result, nil
	}

	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}

	detectCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	page, err := d.pool.Acquire(detectCtx)
	if err != nil {
		return result, fmt.Errorf("storageinj: failed to acquire browser page: %w", err)
	}
	defer d.pool.Release(page)

	// Navigate to target and capture baseline DOM
	if err := page.Navigate(detectCtx, targetURL); err != nil {
		return result, nil // Navigation failure is not an error, just skip
	}

	// Test injection for each storage type
	d.testInjection(detectCtx, page, targetURL, result, opts)

	// Check for sensitive data in storage
	if opts.CheckSensitive {
		d.checkSensitiveData(detectCtx, page, targetURL, result)
	}

	return result, nil
}

// testInjection tests each storage type for DOM reflection.
func (d *Detector) testInjection(ctx context.Context, page *headless.Page, targetURL string, result *DetectionResult, opts DetectOptions) {
	for _, st := range storageinj.StorageTypes() {
		payloads := storageinj.GetPayloads(st)
		if opts.MaxPayloads > 0 && len(payloads) > opts.MaxPayloads {
			payloads = payloads[:opts.MaxPayloads]
		}

		for _, payload := range payloads {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Set the payload in the appropriate storage
			if err := d.setStorage(ctx, page, st, payload); err != nil {
				if d.verbose {
					fmt.Printf("[!] Failed to set %s payload: %v\n", st, err)
				}
				continue
			}

			// Reload the page to trigger rendering with storage values
			if err := page.Navigate(ctx, targetURL); err != nil {
				continue
			}

			// Check if the marker appears in the DOM
			dom, err := page.GetDOM(ctx)
			if err != nil {
				continue
			}

			if strings.Contains(dom, payload.Marker) {
				if d.verbose {
					fmt.Printf("[+] Storage injection found via %s: %s\n", st, payload.Description)
				}
				finding := core.NewFinding("Client-Side Storage Injection", core.SeverityHigh)
				finding.URL = targetURL
				finding.Description = fmt.Sprintf("Unsafe DOM reflection of %s value detected. %s",
					st, payload.Description)
				finding.Evidence = fmt.Sprintf("Storage: %s\nPayload: %s\nMarker '%s' found in DOM after page reload",
					st, payload.Value, payload.Marker)
				finding.Tool = "internal-storageinj"
				finding.Remediation = "Sanitize all values read from client-side storage before inserting into the DOM. Use textContent instead of innerHTML."
				finding.WithOWASPMapping(
					[]string{"WSTG-CLNT-12"},
					[]string{"A03:2025"},
					[]string{"CWE-79"},
				)
				result.Findings = append(result.Findings, finding)
				result.Vulnerable = true
				break // One finding per storage type is enough
			}
		}
	}
}

// checkSensitiveData checks for sensitive information stored in client-side storage.
func (d *Detector) checkSensitiveData(ctx context.Context, page *headless.Page, targetURL string, result *DetectionResult) {
	// Check localStorage
	localData, err := page.GetLocalStorage(ctx)
	if err == nil {
		d.checkKeysForSensitiveData(localData, "localStorage", targetURL, result)
	}

	// Check sessionStorage
	sessionData, err := page.GetSessionStorage(ctx)
	if err == nil {
		d.checkKeysForSensitiveData(sessionData, "sessionStorage", targetURL, result)
	}
}

// checkKeysForSensitiveData checks storage keys against sensitive patterns.
func (d *Detector) checkKeysForSensitiveData(data map[string]string, storageName, targetURL string, result *DetectionResult) {
	for key := range data {
		keyLower := strings.ToLower(key)
		for _, pattern := range storageinj.SensitiveKeyPatterns {
			if strings.Contains(keyLower, pattern) {
				if d.verbose {
					fmt.Printf("[+] Sensitive data in %s: key=%q matches pattern %q\n", storageName, key, pattern)
				}
				finding := core.NewFinding("Sensitive Data in Client Storage", core.SeverityMedium)
				finding.URL = targetURL
				finding.Parameter = key
				finding.Description = fmt.Sprintf("Sensitive data key '%s' found in %s (matches pattern: %s). "+
					"Client-side storage is accessible to JavaScript and may be leaked via XSS.",
					key, storageName, pattern)
				finding.Evidence = fmt.Sprintf("Storage: %s\nKey: %s\nPattern: %s", storageName, key, pattern)
				finding.Tool = "internal-storageinj"
				finding.Remediation = "Avoid storing sensitive data in client-side storage. Use HttpOnly cookies for session tokens. Use server-side sessions for sensitive data."
				finding.WithOWASPMapping(
					[]string{"WSTG-SESS-02"},
					[]string{"A02:2025"},
					[]string{"CWE-922"},
				)
				result.Findings = append(result.Findings, finding)
				result.Vulnerable = true
				break // One finding per key is enough
			}
		}
	}
}

// setStorage sets a payload value in the appropriate storage mechanism.
func (d *Detector) setStorage(ctx context.Context, page *headless.Page, st storageinj.StorageType, payload storageinj.Payload) error {
	switch st {
	case storageinj.LocalStorage:
		return page.SetLocalStorage(ctx, "skws_test", payload.Value)
	case storageinj.SessionStorage:
		return page.SetSessionStorage(ctx, "skws_test", payload.Value)
	case storageinj.Cookie:
		return page.SetCookie(ctx, "skws_test", payload.Value)
	case storageinj.WindowName:
		return page.SetWindowName(ctx, payload.Value)
	default:
		return fmt.Errorf("unknown storage type: %s", st)
	}
}

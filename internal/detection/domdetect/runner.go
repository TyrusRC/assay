// Package domdetect provides DOM-aware vulnerability detection via a
// pluggable browser Runner — letting the same detection logic run in
// production against a real chromedp page and in tests against a fake.
//
// Three sinks are covered, all of which are unreachable from pure HTTP
// response inspection:
//   - DOM-based XSS (script execution observable only after JS runs).
//   - Client-side prototype pollution (Object.prototype mutation).
//   - DOM-based open redirect (window.location set by client JS).
//
// Each detector navigates the Runner to a URL carrying a canary payload,
// then evaluates a JavaScript probe that returns evidence of the sink
// firing. A unique sentinel string per probe prevents cross-target FPs
// from leaking between concurrent scans.
package domdetect

import "context"

// Runner is the minimal browser surface the DOM detectors depend on.
// internal/headless.Page satisfies this via a thin adapter; tests use
// FakeRunner directly.
type Runner interface {
	Navigate(ctx context.Context, url string) error
	EvalJS(ctx context.Context, expr string) (string, error)
}

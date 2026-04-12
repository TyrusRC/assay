// Package headless provides a browser context pool for client-side security testing.
//
// It manages a pool of headless Chrome browser contexts using chromedp,
// providing methods for navigating pages, evaluating JavaScript, and
// interacting with client-side storage (localStorage, sessionStorage,
// cookies, window.name).
//
// When Chrome is not available, NewPool returns ErrBrowserUnavailable,
// allowing the scanner to degrade gracefully.
package headless

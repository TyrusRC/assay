// Package postmsg detects pages that listen for window.postMessage()
// events without validating event.origin against an allowlist.
//
// Why this needs a real browser:
// A static analysis can find addEventListener('message', ...) and look
// for an origin check, but it cannot determine whether the listener's
// branch that mutates DOM/storage actually requires the origin check
// to have passed. The dynamic probe does the only test that matters —
// it dispatches a synthetic MessageEvent claiming an attacker-controlled
// origin and observes whether the listener wrote attacker-controlled
// data to a sink anyway. Nuclei templates structurally cannot do this
// because they do not have a JavaScript runtime.
//
// The probe runs inside a real browser via internal/headless.Page, so
// the listener executes as the application would for any real cross-
// origin postMessage call.
//
// OWASP mappings:
//   - WSTG-CLNT-11 (Testing Web Messaging)
//   - A03:2025 (Injection)
//   - A04:2025 (Insecure Design)
//   - CWE-346 (Origin Validation Error)
//   - CWE-942 (Permissive Cross-domain Policy with Untrusted Domains)
package postmsg

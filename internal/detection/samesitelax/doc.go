// Package samesitelax flags auth-bearing cookies whose SameSite
// attribute leaves the app exposed to top-level GET CSRF. Modern
// browsers default missing-SameSite to Lax, which still permits
// cross-site GET navigation to carry the cookie — so any state-
// changing endpoint reachable via GET is exploitable.
//
// The base finding is Low severity (configuration). When
// DetectOptions.ProbeLogoutPaths is enabled, the detector probes
// well-known logout paths with GET, and if any one invalidates the
// session (Set-Cookie clearing the auth cookie, or 30x redirect to
// a login page) the finding is promoted to Medium with the
// confirmed GET endpoint named in the evidence.
//
// SameSite=Strict is treated as safe. SameSite=None is treated the
// same as Lax for CSRF purposes (cross-site GET still carries the
// cookie); auditing the Secure flag for None is left to other
// detectors.
package samesitelax

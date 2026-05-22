// Package jkuabuse probes for JWT libraries that trust the jku (JSON
// Web Key Set URL) or x5u (X.509 URL) header value when verifying a
// token. RFC 8725 §3.4 explicitly forbids accepting these from the
// token header without an exact-match allowlist; libraries that do
// accept them give an attacker complete control over the key material
// used to validate the token's signature.
//
// The detector forges a JWT with a jku pointing at an attacker-
// controlled URL, sends it to the target, then asks the configured
// CallbackChecker whether the URL was visited inside the poll window.
// The fetch alone is the finding — what the server eventually does
// with the JWKS it finds at that URL is a follow-up confirmation, but
// any server that fetches an arbitrary client-supplied URL is already
// vulnerable.
//
// Requires a baseline (valid) token to derive the payload from and an
// OOB callback primitive (interactsh or a local equivalent). Without
// both, the probe is a no-op.
package jkuabuse

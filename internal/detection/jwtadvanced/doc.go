// Package jwtadvanced actively probes a JWT-authenticated HTTP endpoint
// to confirm whether forged tokens are accepted, complementing the
// passive analysis in internal/detection/jwt/.
//
// The existing jwt package generates forged tokens (alg=none variants,
// embedded JWK, kid path traversal) and inspects token structure, but
// it never asks the server "would you accept this?" — leaving the most
// important question to the analyst. jwtadvanced closes that gap: it
// sends a baseline request with the user-supplied valid token, captures
// the success status, then replays each forgery against the same
// endpoint and reports any forgery that produced an indistinguishable
// authoritative response.
//
// Forgeries tested (each can fire independently):
//   - alg=none, None, NONE, nOnE   — CVE-2015-2951
//   - empty signature segment       — naive "no sig present, skip verify"
//   - kid path traversal to /dev/null — empty-HMAC bypass
//   - duplicate alg header          — parser differential between the
//     verifier and the policy engine
//   - truncated signature           — last byte dropped, exposes
//     verifiers that compare prefix length without constant-time
//     equality
//
// Delivery mechanism: Authorization: Bearer <token> by default. If
// TokenParam is set, the token rides in that query parameter instead —
// some APIs (especially older OAuth deployments) accept access_token
// as a URL parameter.
//
// OWASP mappings:
//   - WSTG-ATHN-04 (Bypass Authentication Schema)
//   - API2:2023 (Broken Authentication)
//   - A07:2025 (Identification and Authentication Failures)
//   - CWE-287, CWE-347
package jwtadvanced

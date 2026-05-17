// Package oauthflow audits OAuth 2.0 / OIDC authorization flow behavior
// against RFC-level abuse paths. Unlike the sibling `oauth` package which
// focuses on discovery-document smells, oauthflow drives the
// authorization and token endpoints directly with crafted requests and
// reasons about their dynamic response.
//
// The four sub-checks shipped here are:
//
//   - DetectStateBinding         — `state` parameter is missing, accepted
//     when omitted, or trivially replayable across sessions (RFC 6749
//     §10.12 CSRF protection).
//   - DetectRedirectURIMatching  — the IdP performs partial / suffix /
//     path-traversal matching on `redirect_uri` instead of the
//     byte-for-byte exact match mandated by RFC 6749 §3.1.2.2 and
//     RFC 9700 §4.1.
//   - DetectPKCEDowngrade        — an authorization request carrying
//     `code_challenge` + `code_challenge_method=S256` can still be
//     exchanged at the token endpoint without supplying a matching
//     `code_verifier` (RFC 7636 / RFC 9700).
//   - DetectIDTokenAlgNone       — an ID-token whose JOSE header declares
//     `alg: none` is accepted by a token-validation surface (RFC 7519,
//     CVE-class JWT alg confusion).
//
// All findings are mapped to WSTG-ATHZ-04 and OWASP Top 10 2025 A07,
// with CWE-352, CWE-601, CWE-345 or CWE-1004 attached per check.
package oauthflow

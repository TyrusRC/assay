// Package sessionlifecycle provides detection for session lifecycle policy
// weaknesses (token refresh rotation, post-logout invalidation, and concurrent
// session policy).
//
// Detection techniques:
//   - Refresh-token rotation: log in, exchange the refresh token, and verify
//     that the issued refresh token (and access token) actually rotate.
//   - Stale-token invalidation: log in, call logout, then re-use the old
//     access token against a protected resource and check that it is rejected.
//   - Concurrent session policy: log in twice as the same user and verify that
//     the first session is invalidated when single-session is required.
//
// OWASP mappings:
//   - WSTG-SESS-01 (Session Management Schema)
//   - WSTG-SESS-06 (Testing for Logout Functionality)
//   - A07:2025 (Identification and Authentication Failures)
//   - CWE-613 (Insufficient Session Expiration)
package sessionlifecycle

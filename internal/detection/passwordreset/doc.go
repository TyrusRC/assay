// Package passwordreset detects flaws in password-reset flows that lead
// to account takeover.
//
// Three sub-checks are implemented:
//
//  1. Host-header injection in reset link — the reset endpoint accepts
//     an attacker-controlled Host header and produces a reset URL (or
//     echoed body) pointing at the attacker's domain, so the
//     transactional email link would carry the attacker's host.
//  2. Cross-user token acceptance — a token issued for user A can be
//     replayed to change user B's password, meaning the reset token is
//     not bound to the target account.
//  3. Reset-token replay — a reset token can be submitted more than
//     once, meaning the token is not invalidated after first use.
//
// All probes are benign and stateful only within the target's test
// surface (we never alter production accounts). Findings carry OWASP
// WSTG-ATHN-09, A07:2025, and CWE-640 / CWE-294 mappings.
package passwordreset

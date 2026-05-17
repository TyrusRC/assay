// Package dnsrebinding provides passive/heuristic detection of DNS rebinding
// susceptibility in SSRF allowlists.
//
// Without controlling an attacker DNS server we cannot truly demonstrate a
// TOCTOU rebinding attack. Instead this package combines a handful of
// signals that, taken together, indicate a server is at risk:
//
//   - Short-TTL multi-IP hostnames whose A-records mix public and private
//     scopes (the classic rebinding setup).
//   - Allowlist bypass via well-known wildcard DNS services (nip.io, xip.io,
//     localtest.me) that resolve to RFC1918 / loopback addresses.
//   - An optional TOCTOU window probe against a configured rebinding test
//     host the operator has spun up themselves.
//
// Findings map to WSTG-INPV-19 (SSRF), A10:2025 and CWE-918/CWE-350.
package dnsrebinding

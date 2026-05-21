// Package http2desync probes for desync attacks that the existing
// smuggling/ (CL.TE, TE.CL, TE.TE) and http2advanced/ (HPACK pollution,
// SETTINGS flood, flow-control exhaustion) packages do not cover.
//
// Added techniques:
//
//   - cl0_desync — Content-Length: 0 with a smuggled request in the
//     body. Frontends that honor CL forward an empty body to the
//     backend; backends that read the socket regardless treat the body
//     as the start of the next request, desyncing the queue. Detection
//     is by timing diff: a desynced backend stalls waiting for more
//     bytes (since it expects to keep reading the smuggled request's
//     headers), so the response is significantly delayed compared to a
//     clean baseline.
//
//   - h2c_upgrade — frontend accepts Upgrade: h2c and returns
//     101 Switching Protocols. Cleartext HTTP/2 upgrade is rarely safe
//     in production: it opens a smuggling primitive where the frontend
//     hands off the upgraded socket to a backend speaking plain HTTP/1
//     and any subsequent bytes are interpreted as h1 requests.
//
// Both probes use raw TCP rather than net/http, because net/http
// normalizes headers in ways that defeat desync testing.
//
// OWASP mappings:
//   - WSTG-INPV-15 (Testing for HTTP Request Smuggling)
//   - A05:2025 (Security Misconfiguration)
//   - CWE-444 (Inconsistent Interpretation of HTTP Requests)
package http2desync

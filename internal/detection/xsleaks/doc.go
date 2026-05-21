// Package xsleaks detects cross-site leak (XS-Leak) primitives in HTTP
// responses by correlating isolation-policy gaps with the request path
// and cookie behavior.
//
// Why correlation, not single-header alerts:
// A missing Cross-Origin-Opener-Policy header in isolation is a low-
// value defense-in-depth finding. The same gap on an authenticated
// account endpoint that ships SameSite=Lax cookies is an exploitable
// xsleak primitive — an attacker can pop the page in a window and use
// window.length / navigation timing / error events to leak user state.
// secheaders/ already catches isolated header gaps; xsleaks/ fires only
// when multiple primitives combine into actual leak capability.
//
// Primitives flagged:
//   - framable                — no X-Frame-Options DENY/SAMEORIGIN and
//     no CSP frame-ancestors restricting framing → frame-count leak
//     primitive available
//   - no_coop                 — no Cross-Origin-Opener-Policy → popup
//     primitives (window.length, named-target reuse, navigation timing)
//   - no_coep                 — no Cross-Origin-Embedder-Policy →
//     Spectre-class side channels still possible
//   - no_corp                 — no Cross-Origin-Resource-Policy →
//     resource loadable cross-origin for timing/size leaks
//   - samesite_cross_site     — cookies sent on cross-site GET
//     (SameSite=None, Lax, or absent) → auth context available to
//     attacker frame/window
//   - auth_sensitive_path     — URL path matches /account, /me, /admin,
//     /dashboard, /profile, /settings → real attack surface
//   - json_response           — Content-Type indicates a data endpoint
//     (raises the value of no_corp findings)
//
// OWASP mappings:
//   - WSTG-CLNT-13 (Testing for Cross-Site Script Inclusion / xsleaks)
//   - A01:2025 (Broken Access Control)
//   - A04:2025 (Insecure Design)
//   - CWE-200  (Exposure of Sensitive Information)
//   - CWE-1021 (Improper Restriction of Rendered UI Layers)
package xsleaks

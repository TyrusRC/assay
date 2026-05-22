// Package authbypass403 probes for 401/403 access-control bypass via
// reverse-proxy trust headers and path-encoding tricks that frontend
// ACLs and backend routers parse differently.
//
// The probe bails when the baseline response isn't already 401/403 —
// there's nothing to bypass on an unprotected URL. When the baseline is
// protected, the detector sweeps a small set of well-known variants
// (X-Original-URL, X-Rewrite-URL, X-Forwarded-For=127.0.0.1,
// X-Custom-IP-Authorization, ;jsessionid-style truncation, /..; path-
// parameter, trailing-slash flip) and reports any variant that returns
// a 2xx (or a clearly distinct non-403 response).
package authbypass403

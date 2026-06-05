// Package api implements the HTTP JSON API behind `assay serve`: it accepts
// scan requests, runs them asynchronously through a pluggable Runner, tracks
// job state in an in-memory store, and renders results in any report format.
// It is transport-only; the React dashboard consumes these endpoints.
package api

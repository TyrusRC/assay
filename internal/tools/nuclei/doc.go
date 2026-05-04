// Package nuclei wraps the projectdiscovery/nuclei binary as a tools.Tool.
//
// The internal template engine in internal/templates/ runs Nuclei-compatible
// YAML templates in-process. This wrapper is the complement: when the user
// has the upstream `nuclei` binary on $PATH, the scanner can dispatch full
// Nuclei runs (community templates, CVE checks, fingerprints) and merge the
// findings back into the unified report. The two engines coexist — the
// in-process executor is preferred for tight integration with discovery
// and authentication state, while the binary wrapper exists to reach the
// 8000+ community templates the user already has installed.
//
// The wrapper invokes nuclei with `-jsonl` to read line-delimited JSON
// findings, parses them into core.Finding, and applies a best-effort
// CWE/severity mapping. OWASP A/API mappings are not derivable from the
// upstream JSON, so they are left empty for Nuclei findings — consumers
// that need them can post-process.
package nuclei

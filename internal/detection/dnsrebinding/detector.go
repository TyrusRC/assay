// Package dnsrebinding probes for DNS-rebinding susceptibility — the
// short-TTL / mixed-scope A-record family and the SSRF-allowlist bypass
// that follows when the application validates the hostname rather than
// the resolved IP.
//
// File layout:
//
//	detector.go  — types, constructor, options
//	probes.go    — the three probe methods (DetectShortTTLMultiIP,
//	               DetectAllowlistBypass, DetectAll)
//	findings.go  — Finding builders + TOCTOU probe
//	helpers.go   — DNS / URL parsing utilities
package dnsrebinding

import (
	"context"
	"net"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

// Detection type strings (exposed as constants because they appear in
// findings and tests assert against them).
const (
	// TypeShortTTLMultiIP labels findings raised by the short-TTL /
	// mixed-scope multi-IP heuristic.
	TypeShortTTLMultiIP = "DNS Rebinding Susceptible (Short TTL Multi-IP)"
	// TypeAllowlistBypass labels findings where the application accepted
	// a request to a hostname that resolves into a private/loopback IP
	// (rebinding-friendly DNS service).
	TypeAllowlistBypass = "SSRF Allowlist Bypass via Hostname Resolution"
	// TypeTOCTOU labels findings raised by the consecutive-request
	// TOCTOU probe against a configured rebinding test host.
	TypeTOCTOU = "DNS Rebinding TOCTOU Window Susceptibility"

	toolName = "dnsrebinding-detector"
)

// rebindBypassHosts is the curated list of public wildcard-DNS
// hostnames that resolve to RFC1918 / loopback addresses. A target that
// fetches any of these has effectively no DNS-based allowlist
// enforcement.
var rebindBypassHosts = []string{
	"localtest.me",           // -> 127.0.0.1
	"127.0.0.1.nip.io",       // -> 127.0.0.1
	"10.0.0.1.nip.io",        // -> 10.0.0.1
	"169.254.169.254.nip.io", // -> 169.254.169.254 (cloud metadata)
	"127.0.0.1.xip.io",       // legacy xip.io (may be defunct, kept for completeness)
}

// baselineBogusHost is a guaranteed-nonexistent hostname used to
// establish "what does a failed fetch look like?" against the target
// endpoint.
const baselineBogusHost = "definitely-not-a-real-host-12345.invalid"

// Resolver is the minimal DNS surface this package needs. Defining it
// as an interface lets tests inject canned answers without going to the
// network.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Detector performs DNS-rebinding susceptibility detection.
type Detector struct {
	client   *http.Client
	resolver Resolver
}

// New constructs a Detector with the default system resolver.
func New(client *http.Client) *Detector {
	return &Detector{
		client:   client,
		resolver: net.DefaultResolver,
	}
}

// WithResolver overrides the resolver (primarily for tests).
func (d *Detector) WithResolver(r Resolver) *Detector {
	d.resolver = r
	return d
}

// DetectOptions configures a detection run.
type DetectOptions struct {
	// SSRFParam is the request parameter that accepts a URL (required
	// for the allowlist-bypass leg).
	SSRFParam string
	// RebindingTestHost, when set, is the operator-controlled hostname
	// used to perform the TOCTOU probe. Empty means we only emit an
	// Informational note.
	RebindingTestHost string
	// Timeout caps each individual probe request.
	Timeout time.Duration
	// EmitInformational controls whether we surface the "TOCTOU probe
	// skipped" informational finding when RebindingTestHost is empty.
	EmitInformational bool
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		Timeout:           10 * time.Second,
		EmitInformational: false,
	}
}

// DetectionResult is the aggregated outcome of a detector method.
type DetectionResult struct {
	Vulnerable    bool
	Findings      []*core.Finding
	DetectionType string
}

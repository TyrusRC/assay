package samesitescript

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
)

// Detector is the scanner-side wrapper. It accepts a target URL,
// extracts the eTLD+1, runs Evaluate() with a real DNS resolver, and
// emits one Finding per misconfigured subdomain.
type Detector struct {
	resolver Resolver
	verbose  bool
}

// New constructs a Detector using net.DefaultResolver. Tests inject
// a stub Resolver via NewWithResolver.
func New() *Detector {
	return &Detector{resolver: defaultResolver}
}

// NewWithResolver constructs a Detector with the supplied Resolver.
func NewWithResolver(r Resolver) *Detector {
	if r == nil {
		r = defaultResolver
	}
	return &Detector{resolver: r}
}

// WithVerbose toggles diagnostic output.
func (d *Detector) WithVerbose(v bool) *Detector {
	d.verbose = v
	return d
}

// DetectOptions tunes the probe. There are no HTTP knobs because the
// check is pure DNS.
type DetectOptions struct{}

// DefaultOptions returns sensible defaults.
func DefaultOptions() DetectOptions { return DetectOptions{} }

// DetectionResult mirrors the scanner convention.
type DetectionResult struct {
	URL        string
	Domain     string
	Analysis   Result
	Findings   []*core.Finding
	Vulnerable bool
}

// Detect parses the URL, runs Evaluate, and emits findings.
func (d *Detector) Detect(ctx context.Context, target string, _ DetectOptions) (*DetectionResult, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("samesitescript: parse URL: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("samesitescript: URL has no host: %q", target)
	}
	// Skip raw IPs — the check only makes sense for DNS-resolved domains.
	if net.ParseIP(host) != nil {
		return &DetectionResult{URL: target, Domain: host}, nil
	}
	// For multi-label hostnames (foo.bar.example.com) we want the parent
	// (example.com) so the subdomain probes don't double-stack the
	// "localhost.foo." prefix onto an already-subdomained name.
	domain := publicSuffixPlusOne(host)
	if domain == "" {
		domain = host
	}

	// Allow context cancellation between probes by wrapping the
	// supplied resolver.
	wrapped := func(name string) ([]net.IP, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return d.resolver(name)
	}

	analysis := Evaluate(domain, wrapped)
	result := &DetectionResult{
		URL:        target,
		Domain:     domain,
		Analysis:   analysis,
		Vulnerable: analysis.Vulnerable,
	}
	if analysis.Vulnerable {
		for _, host := range analysis.MisconfiguredHosts {
			result.Findings = append(result.Findings, d.toFinding(target, domain, host))
		}
	}
	return result, nil
}

func (d *Detector) toFinding(target, domain, host string) *core.Finding {
	f := core.NewFinding("same_site_scripting", core.SeverityMedium)
	f.Tool = "samesitescript"
	f.URL = target
	f.Title = "Same-Site Scripting via DNS misconfiguration"
	f.Confidence = core.ConfidenceHigh
	f.Description = "A subdomain of " + domain + " resolves to a loopback / unspecified IP. " +
		"Any HTTP service running on that loopback (developer tools, debug dashboards, package managers) is reachable as a same-eTLD+1 origin, " +
		"so JavaScript served from it can read non-HttpOnly cookies and localStorage shared with the production site. " +
		"First described by Tavis Ormandy (2008)."
	f.Evidence = "DNS: " + host + " → loopback/unspecified address"
	f.Metadata["misconfigured_host"] = host
	f.Metadata["parent_domain"] = domain
	f.Remediation = "Remove the wildcard / loopback DNS record for " + host + ". " +
		"If a localhost-style name is required for development, host it under a separate eTLD+1 (e.g. localhost.dev) so cookies don't share an origin with production."
	f.References = []string{
		"https://lcamtuf.coredump.cx/clobber.txt",
	}
	f = f.WithOWASPMapping(
		[]string{"WSTG-CONF-10"},
		[]string{"A05:2021"},
		[]string{"CWE-942"},
	)
	return f
}

func defaultResolver(host string) ([]net.IP, error) {
	return net.LookupIP(host)
}

// publicSuffixPlusOne is a lightweight eTLD+1 extractor. It returns the
// last two labels of the hostname, which is correct for the common
// `foo.bar.example.com` → `example.com` case. It is intentionally not
// full PSL-aware — the AWVS check itself uses a simple heuristic — but
// the prefix-probes still hit the right plate even for `co.uk`-class
// suffixes because the misconfiguration appears at every subdomain.
func publicSuffixPlusOne(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

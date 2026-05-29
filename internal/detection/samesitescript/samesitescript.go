// Package samesitescript detects the "Same-Site Scripting" DNS
// misconfiguration first described by Tavis Ormandy (2008): a DNS record
// like `localhost.victim.com A 127.0.0.1` (or `.0.0.0.0`, `.::1`) means
// any JavaScript served from that subdomain runs in the same eTLD+1 as
// the production site, inheriting cookies (without HttpOnly) and reading
// localStorage shared by the parent domain.
//
// The check is purely DNS-driven — no HTTP traffic to the victim — so it
// runs cheaply and avoids tripping rate limits.
//
// Mirrors AWVS Same_Site_Scripting.script.
//
// References: tavis.io / Project Zero archive, OWASP Same-Site Scripting page.
package samesitescript

import (
	"net"
	"strings"
)

// Resolver abstracts net.LookupIP so tests can stub DNS without sockets.
type Resolver func(host string) ([]net.IP, error)

// Result reports the evaluation outcome.
type Result struct {
	Vulnerable         bool
	MisconfiguredHosts []string
	Notes              string
}

// ProbeHosts returns the subdomain candidates that, if they resolve to a
// loopback or all-zero address, indicate the misconfiguration.
func ProbeHosts(domain string) []string {
	d := strings.TrimSpace(strings.ToLower(domain))
	if d == "" {
		return nil
	}
	return []string{
		"localhost." + d,
		"127.0.0.1." + d,
		"0.0.0.0." + d,
		"local." + d,
		"loopback." + d,
	}
}

// Evaluate checks each probe host with the supplied resolver. A host
// resolving to a loopback / all-zero / link-local-loopback IP is the
// positive signal. Resolver errors are treated as "no evidence" rather
// than as positive matches.
func Evaluate(domain string, resolve Resolver) Result {
	d := strings.TrimSpace(domain)
	if d == "" || resolve == nil {
		return Result{}
	}
	var hits []string
	for _, h := range ProbeHosts(d) {
		ips, err := resolve(h)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if isLoopbackOrZero(ip) {
				hits = append(hits, h)
				break
			}
		}
	}
	if len(hits) == 0 {
		return Result{}
	}
	return Result{
		Vulnerable:         true,
		MisconfiguredHosts: hits,
		Notes:              "DNS record points to a loopback/zero address. Any JavaScript served from this name shares the eTLD+1 origin with the production site and inherits non-HttpOnly cookies.",
	}
}

func isLoopbackOrZero(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	if ip.IsUnspecified() {
		return true
	}
	// IPv4-mapped IPv6 loopback (::ffff:127.0.0.1).
	if v4 := ip.To4(); v4 != nil && v4.IsLoopback() {
		return true
	}
	return false
}

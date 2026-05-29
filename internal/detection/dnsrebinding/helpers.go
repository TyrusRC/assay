package dnsrebinding

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/TyrusRC/assay/internal/http"
)

// hostFromURL extracts the hostname portion of a URL, returning an error
// only when the URL is unparseable.
func hostFromURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	h := u.Hostname()
	if h == "" {
		// Treat "no host" as an empty hostname rather than an error so
		// the caller can decide; but also surface as an error when the
		// original string didn't even contain a scheme.
		if !strings.Contains(raw, "://") {
			return "", fmt.Errorf("URL %q has no scheme", raw)
		}
	}
	return h, nil
}

// classifyScope returns whether the given IPs contain any
// private/loopback (hasPrivate) and any public-routable (hasPublic)
// addresses.
func classifyScope(ips []net.IPAddr) (hasPrivate, hasPublic bool) {
	for _, a := range ips {
		if a.IP == nil {
			continue
		}
		if isPrivateOrSpecial(a.IP) {
			hasPrivate = true
		} else {
			hasPublic = true
		}
	}
	return
}

// isPrivateOrSpecial reports whether the IP belongs to a scope an SSRF
// allowlist would normally reject.
func isPrivateOrSpecial(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	// 169.254.169.254 / 100.100.100.200 are already covered by IsLinkLocalUnicast.
	return false
}

// ipsChanged reports whether the two resolutions returned different sets.
func ipsChanged(a, b []net.IPAddr) bool {
	if len(b) == 0 {
		return false
	}
	seen := make(map[string]bool, len(a))
	for _, x := range a {
		seen[x.IP.String()] = true
	}
	for _, y := range b {
		if !seen[y.IP.String()] {
			return true
		}
	}
	// Symmetric check.
	seenB := make(map[string]bool, len(b))
	for _, y := range b {
		seenB[y.IP.String()] = true
	}
	for _, x := range a {
		if !seenB[x.IP.String()] {
			return true
		}
	}
	return false
}

func joinIPs(ips []net.IPAddr) string {
	if len(ips) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(ips))
	for _, a := range ips {
		parts = append(parts, a.IP.String())
	}
	return strings.Join(parts, ", ")
}

// looksLikeFetchSuccess reports whether resp looks meaningfully
// different from the baseline-bogus response in a way that suggests
// the server did in fact fetch the URL.
func looksLikeFetchSuccess(resp, baseline *http.Response, baselineErr error) bool {
	if resp == nil {
		return false
	}
	// A 2xx response strongly suggests success.
	is2xx := resp.StatusCode >= 200 && resp.StatusCode < 300
	if baseline == nil || baselineErr != nil {
		// No baseline to compare against — fall back to "2xx with body".
		return is2xx && len(resp.Body) > 0
	}
	if resp.StatusCode == baseline.StatusCode {
		// Same status — only call it success if the body diverged
		// noticeably.
		return len(resp.Body) > 0 && len(resp.Body) != len(baseline.Body) && is2xx
	}
	// Different status: 2xx vs anything else is a strong signal.
	return is2xx
}

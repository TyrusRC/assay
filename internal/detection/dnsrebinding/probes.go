package dnsrebinding

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

// DetectShortTTLMultiIP probes the target's hostname for short-TTL or
// mixed-scope DNS records. The check is heuristic: stdlib does not
// expose TTL, so we simulate "short TTL" by doing two resolutions
// within a 5 s window and treating any change as evidence of a very
// short TTL.
func (d *Detector) DetectShortTTLMultiIP(ctx context.Context, targetURL string) (*DetectionResult, error) {
	result := &DetectionResult{
		DetectionType: TypeShortTTLMultiIP,
		Findings:      []*core.Finding{},
	}

	host, err := hostFromURL(targetURL)
	if err != nil {
		return result, err
	}
	if host == "" {
		return result, errors.New("targetURL has no host")
	}
	// Skip when the host is a literal IP — DNS rebinding requires a name.
	if net.ParseIP(host) != nil {
		return result, nil
	}

	round1, err := d.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return result, fmt.Errorf("dns lookup failed: %w", err)
	}

	// Second resolution within a short window simulates the TTL probe.
	round2, err2 := d.resolver.LookupIPAddr(ctx, host)
	if err2 != nil {
		round2 = nil // non-fatal: still evaluate round1
	}

	allIPs := append([]net.IPAddr{}, round1...)
	allIPs = append(allIPs, round2...)

	hasPrivate, hasPublic := classifyScope(allIPs)
	changedBetweenRounds := ipsChanged(round1, round2)

	// Flag when round-to-round answers differ AND the combined set
	// mixes private + public scopes, OR when a single round already
	// contains both scopes (the classic multi-IP rebinding setup).
	mixedSingleRound := hasPrivate && hasPublic
	if !(mixedSingleRound || (changedBetweenRounds && hasPrivate && hasPublic)) {
		return result, nil
	}

	f := d.buildShortTTLFinding(targetURL, host, round1, round2, mixedSingleRound, changedBetweenRounds)
	result.Findings = append(result.Findings, f)
	result.Vulnerable = true
	return result, nil
}

// DetectAllowlistBypass probes the SSRF endpoint with rebinding-friendly
// hostnames and (optionally) with a configured rebinding test host to
// estimate TOCTOU exposure.
func (d *Detector) DetectAllowlistBypass(ctx context.Context, targetURL, ssrfParam string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{
		DetectionType: TypeAllowlistBypass,
		Findings:      []*core.Finding{},
	}

	if ssrfParam == "" {
		return result, errors.New("ssrfParam is required")
	}
	if d.client == nil {
		return result, errors.New("http client is nil")
	}

	probeCtx := ctx
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		probeCtx, cancel = context.WithTimeout(ctx, opts.Timeout*time.Duration(len(rebindBypassHosts)+3))
		defer cancel()
	}

	// 1. Baseline: send an obviously-bogus host. Most servers will fail
	//    or 5xx; that "failure shape" is what we compare against.
	baseline, baselineErr := d.client.SendPayload(probeCtx, targetURL, ssrfParam, "http://"+baselineBogusHost+"/", "GET")

	// 2. For each rebinding-friendly host, see whether the server
	//    fetched it (response differs from baseline in a "successful
	//    fetch" way).
	for _, h := range rebindBypassHosts {
		select {
		case <-probeCtx.Done():
			return result, probeCtx.Err()
		default:
		}

		payloadURL := "http://" + h + "/"
		resp, err := d.client.SendPayload(probeCtx, targetURL, ssrfParam, payloadURL, "GET")
		if err != nil || resp == nil {
			continue
		}
		if !looksLikeFetchSuccess(resp, baseline, baselineErr) {
			continue
		}
		result.Findings = append(result.Findings, d.buildAllowlistBypassFinding(targetURL, ssrfParam, h, resp))
		result.Vulnerable = true
	}

	// 3. TOCTOU probe.
	if opts.RebindingTestHost != "" {
		toctouFinding := d.toctouProbe(probeCtx, targetURL, ssrfParam, opts.RebindingTestHost, baseline, baselineErr)
		if toctouFinding != nil {
			result.Findings = append(result.Findings, toctouFinding)
			if toctouFinding.Severity == core.SeverityHigh {
				result.Vulnerable = true
			}
		}
	} else if opts.EmitInformational {
		result.Findings = append(result.Findings, d.toctouInformationalFinding(targetURL, ssrfParam))
	}

	return result, nil
}

// DetectAll runs every available DNS-rebinding check and aggregates the
// findings.
func (d *Detector) DetectAll(ctx context.Context, targetURL, ssrfParam string, opts DetectOptions) (*DetectionResult, error) {
	combined := &DetectionResult{
		DetectionType: "DNS Rebinding (All)",
		Findings:      []*core.Finding{},
	}

	if r, err := d.DetectShortTTLMultiIP(ctx, targetURL); err == nil && r != nil {
		combined.Findings = append(combined.Findings, r.Findings...)
		if r.Vulnerable {
			combined.Vulnerable = true
		}
	}

	if ssrfParam != "" {
		if r, err := d.DetectAllowlistBypass(ctx, targetURL, ssrfParam, opts); err == nil && r != nil {
			combined.Findings = append(combined.Findings, r.Findings...)
			if r.Vulnerable {
				combined.Vulnerable = true
			}
		}
	}

	return combined, nil
}

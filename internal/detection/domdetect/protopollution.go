package domdetect

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
)

// ProtoPollutionResult holds the findings from DetectProtoPollution.
type ProtoPollutionResult struct {
	Findings []*core.Finding
}

// DetectProtoPollution probes targetURL for client-side prototype pollution
// by appending the canonical bracket-syntax payload `?__proto__[<sentinel>]=POLLUTED`
// (and a constructor-prototype variant) and then asking the browser whether
// `({})[<sentinel>]` returns "POLLUTED". A polluted Object.prototype is the
// only sink that can produce that signal; pure HTTP reflection cannot.
//
// We also try the JSON-style `?__proto__.<sentinel>=POLLUTED` shape because
// some routers parse dotted keys differently from bracketed ones.
func DetectProtoPollution(ctx context.Context, runner Runner, targetURL string) (*ProtoPollutionResult, error) {
	res := &ProtoPollutionResult{}
	if runner == nil {
		return res, nil
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return res, fmt.Errorf("parse target: %w", err)
	}

	type probe struct {
		paramKey string
		desc     string
	}
	sentinel := newSentinel("skwsPP")
	probes := []probe{
		{"__proto__[" + sentinel + "]", "__proto__ bracket"},
		{"__proto__." + sentinel, "__proto__ dotted"},
		{"constructor[prototype][" + sentinel + "]", "constructor.prototype bracket"},
	}

	for _, p := range probes {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}

		probeURL := setRawQueryParam(u, p.paramKey, "POLLUTED")
		if err := runner.Navigate(ctx, probeURL); err != nil {
			continue
		}

		got, err := runner.EvalJS(ctx, fmt.Sprintf(`(({})[%q]) || ""`, sentinel))
		if err != nil {
			continue
		}
		if !strings.Contains(got, "POLLUTED") {
			continue
		}

		finding := core.NewFinding("Client-Side Prototype Pollution", core.SeverityHigh)
		finding.URL = targetURL
		finding.Parameter = p.paramKey
		finding.Description = fmt.Sprintf(
			"Client-side prototype pollution detected via %s. The application's URL-parameter parser merges keys into Object.prototype, so any subsequent property lookup on a fresh object inherits attacker-controlled values.",
			p.desc,
		)
		finding.Evidence = fmt.Sprintf("Probe: %s=POLLUTED\n({})[\"%s\"] returned: %q", p.paramKey, sentinel, got)
		finding.Tool = "domdetect-protopollution"
		finding.Confidence = core.ConfidenceHigh
		finding.Remediation = "Reject __proto__, constructor, and prototype keys when parsing query strings or merging objects. Freeze Object.prototype with Object.freeze. Use Map for arbitrary-keyed lookups instead of plain objects."
		finding.WithOWASPMapping(
			[]string{"WSTG-CLNT-13"},
			[]string{"A08:2025"},
			[]string{"CWE-1321"},
		)
		res.Findings = append(res.Findings, finding)
		// One confirmed sink is enough; further probes give only redundant evidence.
		return res, nil
	}
	return res, nil
}

// setRawQueryParam appends `<rawKey>=<encodedValue>` to the URL's existing
// raw query, preserving the bracket/dot syntax verbatim — Go's url.Values.
// Encode() would percent-encode the brackets, breaking the prototype-key
// semantics we depend on. The value is still encoded.
func setRawQueryParam(u *url.URL, rawKey, value string) string {
	clone := *u
	encodedVal := url.QueryEscape(value)
	pair := rawKey + "=" + encodedVal
	if clone.RawQuery == "" {
		clone.RawQuery = pair
	} else {
		clone.RawQuery = clone.RawQuery + "&" + pair
	}
	return clone.String()
}

package domdetect

import (
	"context"
	"fmt"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/detection/protopollution"
)

// ProtoPollutionResult holds the findings from DetectProtoPollution.
type ProtoPollutionResult struct {
	Findings []*core.Finding
}

// DetectProtoPollution probes targetURL for client-side prototype pollution.
// It navigates a battery of source vectors that each attempt to set
// Object.prototype[<sentinel>]="POLLUTED" — bracket and dotted __proto__
// notation, the constructor.prototype chain, and the fragment-based
// equivalents (SPAs that parse location.hash into config are a common source
// the query-only check misses) — then asks the browser whether a fresh empty
// object inherits the sentinel value. A polluted Object.prototype is the only
// sink that can produce that signal; pure HTTP reflection cannot.
//
// When pollution is confirmed, the finding enumerates the known gadgets whose
// presence would turn the source into a full source→gadget→sink exploit, so
// triage knows the next step.
func DetectProtoPollution(ctx context.Context, runner Runner, targetURL string) (*ProtoPollutionResult, error) {
	res := &ProtoPollutionResult{}
	if runner == nil {
		return res, nil
	}

	sentinel := newSentinel("skwsPP")
	expr := protopollution.ReadPrototypeExpr(sentinel)

	for _, v := range protopollution.BuildPollutionVectors(targetURL, sentinel, "POLLUTED") {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}

		if err := runner.Navigate(ctx, v.URL); err != nil {
			continue
		}
		got, err := runner.EvalJS(ctx, expr)
		if err != nil || !protopollution.ConfirmsPollution(got, "POLLUTED") {
			continue
		}

		res.Findings = append(res.Findings, buildProtoPollutionFinding(targetURL, v, sentinel, got))
		// One confirmed sink is enough; further probes give only redundant evidence.
		return res, nil
	}
	return res, nil
}

// buildProtoPollutionFinding assembles the confirmed client-side PP finding,
// including the gadget catalog as actionable next steps.
func buildProtoPollutionFinding(targetURL string, v protopollution.PollutionVector, sentinel, got string) *core.Finding {
	finding := core.NewFinding("Client-Side Prototype Pollution", core.SeverityHigh)
	finding.URL = targetURL
	finding.Parameter = v.Name
	finding.Description = fmt.Sprintf(
		"Client-side prototype pollution detected via %s. The application merges attacker-controlled "+
			"keys into Object.prototype, so any subsequent property lookup on a fresh object inherits "+
			"attacker values. Confirmed in the browser: a clean object inherited the injected sentinel.",
		v.Name,
	)
	finding.Evidence = fmt.Sprintf("Vector: %s\n({})[%q] returned: %q\nGadgets to check: %s",
		v.URL, sentinel, got, gadgetSummary())
	finding.Tool = "domdetect-protopollution"
	finding.Confidence = core.ConfidenceHigh
	finding.Remediation = "Reject __proto__, constructor, and prototype keys when parsing query strings or " +
		"merging objects. Freeze Object.prototype with Object.freeze. Use Map for arbitrary-keyed lookups."
	finding.References = []string{
		"https://portswigger.net/research/widespread-prototype-pollution-gadgets",
		"https://portswigger.net/web-security/prototype-pollution/client-side",
	}
	finding.WithOWASPMapping(
		[]string{"WSTG-CLNT-13"},
		[]string{"A08:2025"},
		[]string{"CWE-1321"},
	)
	if finding.Metadata == nil {
		finding.Metadata = make(map[string]interface{})
	}
	finding.Metadata["gadgets"] = gadgetProperties()
	return finding
}

// gadgetSummary renders the gadget catalog as a one-line hint for evidence.
func gadgetSummary() string {
	cat := protopollution.GadgetCatalog()
	parts := make([]string, 0, len(cat))
	for _, g := range cat {
		parts = append(parts, g.Property+" → "+g.Sink)
	}
	return strings.Join(parts, "; ")
}

// gadgetProperties returns just the gadget property names for finding metadata.
func gadgetProperties() []string {
	cat := protopollution.GadgetCatalog()
	out := make([]string, 0, len(cat))
	for _, g := range cat {
		out = append(out, g.Property)
	}
	return out
}

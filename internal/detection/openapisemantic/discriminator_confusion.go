package openapisemantic

import (
	"context"
	"fmt"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
)

// DetectDiscriminatorConfusion probes oneOf/anyOf schemas with a
// discriminator. It sends the "safer" discriminator value (e.g. "user")
// together with fields that only the "privileged" branch (e.g. "admin")
// declares. Acceptance means the server treats the discriminator as a label
// rather than a gate — Critical.
func (d *Detector) DetectDiscriminatorConfusion(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{Findings: []*core.Finding{}, DetectionType: "discriminator-confusion"}
	spec, base, err := d.load(ctx, opts)
	if err != nil {
		return result, err
	}
	for _, ref := range spec.Operations() {
		if ref.Method != "POST" && ref.Method != "PUT" && ref.Method != "PATCH" {
			continue
		}
		schema := ref.Op.JSONSchema()
		if schema == nil {
			continue
		}
		branches, propName := collectDiscriminatorBranches(schema)
		if propName == "" || len(branches) < 2 {
			continue
		}
		safe, priv, privFields := chooseSafeAndPrivileged(branches)
		if safe == "" || priv == "" || len(privFields) == 0 {
			continue
		}
		body := map[string]interface{}{propName: safe}
		for _, f := range privFields {
			body[f] = privilegedValue(f)
		}
		target := joinURL(base, ref.Path)
		resp, err := d.sendJSON(ctx, target, ref.Method, body)
		if err != nil {
			continue
		}
		if !is2xx(resp.StatusCode) {
			continue
		}
		finding := newFinding(core.SeverityCritical, target, propName,
			fmt.Sprintf("Discriminator confusion: %s=%q was accepted alongside %s-only fields %v.", propName, safe, priv, privFields),
			fmt.Sprintf("status=%d body=%s", resp.StatusCode, truncate(resp.Body, 300)),
		)
		result.Findings = append(result.Findings, finding)
	}
	result.Vulnerable = len(result.Findings) > 0
	return result, nil
}

// collectDiscriminatorBranches walks a schema's oneOf/anyOf and returns a
// (label -> required fields) map plus the discriminator property name.
// When a mapping is declared on the discriminator, labels are taken from
// it; otherwise we fall back to the enum on each branch's discriminator
// property.
func collectDiscriminatorBranches(s *Schema) (map[string][]string, string) {
	if s == nil || s.Discriminator == nil || s.Discriminator.PropertyName == "" {
		return nil, ""
	}
	propName := s.Discriminator.PropertyName
	variants := s.OneOf
	if len(variants) == 0 {
		variants = s.AnyOf
	}
	if len(variants) == 0 {
		return nil, ""
	}
	out := map[string][]string{}
	for _, v := range variants {
		if v == nil {
			continue
		}
		label := branchLabel(v, propName)
		if label == "" {
			continue
		}
		// Required fields minus the discriminator itself.
		fields := make([]string, 0, len(v.Required))
		for _, r := range v.Required {
			if r == propName {
				continue
			}
			fields = append(fields, r)
		}
		out[label] = fields
	}
	return out, propName
}

// branchLabel returns the discriminator value associated with one variant —
// either the enum on the discriminator property, or its declared example.
func branchLabel(v *Schema, propName string) string {
	if v == nil || v.Properties == nil {
		return ""
	}
	p, ok := v.Properties[propName]
	if !ok || p == nil {
		return ""
	}
	for _, e := range p.Enum {
		if s, ok := e.(string); ok {
			return s
		}
	}
	if s, ok := p.Example.(string); ok {
		return s
	}
	if s, ok := p.Default.(string); ok {
		return s
	}
	return ""
}

// chooseSafeAndPrivileged picks the "least privileged" label and one
// "privileged" label whose required fields are not in the safe branch.
// The returned privFields are the candidate admin-only properties.
func chooseSafeAndPrivileged(branches map[string][]string) (string, string, []string) {
	if len(branches) < 2 {
		return "", "", nil
	}
	// Prefer well-known labels when present, otherwise fall back to
	// any pair where one branch declares fields the other doesn't.
	prefSafe := []string{"user", "guest", "customer"}
	prefPriv := []string{"admin", "root", "superuser", "staff"}
	var safe, priv string
	for _, s := range prefSafe {
		if _, ok := branches[s]; ok {
			safe = s
			break
		}
	}
	for _, p := range prefPriv {
		if _, ok := branches[p]; ok {
			priv = p
			break
		}
	}
	if safe == "" || priv == "" {
		// Fallback: pick the smallest- and largest-field branches.
		var minLabel, maxLabel string
		minLen, maxLen := -1, -1
		for label, fields := range branches {
			if minLen < 0 || len(fields) < minLen {
				minLen = len(fields)
				minLabel = label
			}
			if len(fields) > maxLen {
				maxLen = len(fields)
				maxLabel = label
			}
		}
		if minLabel == maxLabel {
			return "", "", nil
		}
		safe = minLabel
		priv = maxLabel
	}
	safeSet := map[string]struct{}{}
	for _, f := range branches[safe] {
		safeSet[f] = struct{}{}
	}
	extras := []string{}
	for _, f := range branches[priv] {
		if _, ok := safeSet[f]; !ok {
			extras = append(extras, f)
		}
	}
	return safe, priv, extras
}

// privilegedValue returns a plausible value to slot into an admin-only
// field. Booleans get true; strings get "admin"; everything else gets 1.
func privilegedValue(field string) interface{} {
	lower := strings.ToLower(field)
	switch {
	case strings.HasPrefix(lower, "is_"), strings.HasPrefix(lower, "is"):
		return true
	case strings.Contains(lower, "role"), strings.Contains(lower, "permission"):
		return "admin"
	default:
		return true
	}
}

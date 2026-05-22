package openapisemantic

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
)

// DetectAdditionalPropertiesBypass probes object schemas that explicitly
// disallow extras (`additionalProperties: false`). It sends a privileged
// extra (e.g. `isAdmin: true`); a 2xx response that echoes the field back
// is High — the schema's contract is being ignored.
func (d *Detector) DetectAdditionalPropertiesBypass(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{Findings: []*core.Finding{}, DetectionType: "additional-properties-bypass"}
	spec, base, err := d.load(ctx, opts)
	if err != nil {
		return result, err
	}
	extras := []string{"isAdmin", "role", "is_staff", "is_superuser"}
	for _, ref := range spec.Operations() {
		if ref.Method != "POST" && ref.Method != "PUT" && ref.Method != "PATCH" {
			continue
		}
		schema := ref.Op.JSONSchema()
		if schema == nil || schema.Type != "object" {
			continue
		}
		if schema.AdditionalProperties == nil || !schema.AdditionalProperties.Set {
			continue
		}
		if schema.AdditionalProperties.Allowed {
			continue
		}
		// Build a body with the declared required fields plus one extra.
		body := map[string]interface{}{}
		for _, req := range schema.Required {
			if sub, ok := schema.Properties[req]; ok && sub != nil {
				body[req] = sampleForSchema(sub)
			} else {
				body[req] = "test"
			}
		}
		extra := extras[0]
		body[extra] = true
		target := joinURL(base, ref.Path)
		resp, err := d.sendJSON(ctx, target, ref.Method, body)
		if err != nil {
			continue
		}
		if !is2xx(resp.StatusCode) {
			continue
		}
		if !responseEchoesField(resp.Body, extra) {
			continue
		}
		finding := newFinding(core.SeverityHigh, target, extra,
			fmt.Sprintf("additionalProperties: false on %s violated — extra field %q was accepted and reflected.", ref.Path, extra),
			fmt.Sprintf("status=%d body=%s", resp.StatusCode, truncate(resp.Body, 300)),
		)
		result.Findings = append(result.Findings, finding)
	}
	result.Vulnerable = len(result.Findings) > 0
	return result, nil
}

// responseEchoesField returns true when the server appears to have
// persisted / reflected the named field — either by including it in a JSON
// response or by mentioning the name in a plain-text body. The check is
// deliberately permissive: the alternative (parsing every possible response
// shape) loses too many real findings.
func responseEchoesField(body, field string) bool {
	if body == "" || field == "" {
		return false
	}
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err == nil {
		if _, ok := data[field]; ok {
			return true
		}
	}
	return strings.Contains(body, field)
}

package openapisemantic

import (
	"context"
	"fmt"

	"github.com/TyrusRC/assay/internal/core"
)

// DetectTypeCoercion probes integer fields by sending the value as a quoted
// string. A 2xx response is the informational leg (Low); when the string
// payload carries an injection-shaped value and the response discriminably
// differs from a benign baseline, the finding is elevated to High.
func (d *Detector) DetectTypeCoercion(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{Findings: []*core.Finding{}, DetectionType: "type-coercion"}
	spec, base, err := d.load(ctx, opts)
	if err != nil {
		return result, err
	}
	for _, ref := range spec.Operations() {
		if ref.Method != "POST" && ref.Method != "PUT" && ref.Method != "PATCH" {
			continue
		}
		schema := ref.Op.JSONSchema()
		if schema == nil || schema.Type != "object" {
			continue
		}
		target := joinURL(base, ref.Path)
		for fieldName, prop := range schema.Properties {
			if prop == nil || prop.Type != "integer" {
				continue
			}
			// Step 1 — baseline with a valid integer.
			baseline, err := d.sendJSON(ctx, target, ref.Method, map[string]interface{}{fieldName: 1})
			if err != nil {
				continue
			}
			// Step 2 — same field, value as a quoted numeric string.
			coerced, err := d.sendJSON(ctx, target, ref.Method, map[string]interface{}{fieldName: "1"})
			if err != nil {
				continue
			}
			if !is2xx(coerced.StatusCode) {
				continue
			}
			// Step 3 — injection-shaped string payload.
			injBody := map[string]interface{}{fieldName: "1 OR 1=1"}
			injected, err := d.sendJSON(ctx, target, ref.Method, injBody)
			if err != nil {
				continue
			}
			if is2xx(injected.StatusCode) && responsesDiffer(baseline, injected) {
				f := newFinding(core.SeverityHigh, target, fieldName,
					fmt.Sprintf("OpenAPI %s.%s declared as integer; server accepted string payload %q and response differed from baseline.", ref.Path, fieldName, "1 OR 1=1"),
					fmt.Sprintf("baseline status=%d coerced status=%d injected status=%d", baseline.StatusCode, coerced.StatusCode, injected.StatusCode),
				)
				result.Findings = append(result.Findings, f)
				continue
			}
			// Coercion accepted but no discriminable processing — informational.
			f := newFinding(core.SeverityLow, target, fieldName,
				fmt.Sprintf("OpenAPI %s.%s declared as integer; server accepted quoted string value.", ref.Path, fieldName),
				fmt.Sprintf("baseline status=%d coerced status=%d", baseline.StatusCode, coerced.StatusCode),
			)
			result.Findings = append(result.Findings, f)
		}
	}
	result.Vulnerable = len(result.Findings) > 0
	return result, nil
}

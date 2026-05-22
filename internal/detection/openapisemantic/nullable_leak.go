package openapisemantic

import (
	"context"
	"fmt"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
)

// DetectNullableLeak probes nullable: true fields whose names look like
// credentials (password, token, secret). When the server accepts a null
// value on a creation endpoint, that's a Critical "no password" account.
func (d *Detector) DetectNullableLeak(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{Findings: []*core.Finding{}, DetectionType: "nullable-leak"}
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
		for fieldName, prop := range schema.Properties {
			if prop == nil || !prop.Nullable {
				continue
			}
			if !looksLikeCredential(fieldName) {
				continue
			}
			body := map[string]interface{}{fieldName: nil}
			// Populate sibling required fields with cheap dummies so the
			// request isn't rejected for unrelated reasons.
			for _, req := range schema.Required {
				if req == fieldName {
					continue
				}
				if _, ok := body[req]; ok {
					continue
				}
				if sub, ok := schema.Properties[req]; ok && sub != nil {
					body[req] = sampleForSchema(sub)
				} else {
					body[req] = "test"
				}
			}
			target := joinURL(base, ref.Path)
			resp, err := d.sendJSON(ctx, target, ref.Method, body)
			if err != nil {
				continue
			}
			if !is2xx(resp.StatusCode) {
				continue
			}
			finding := newFinding(core.SeverityCritical, target, fieldName,
				fmt.Sprintf("Nullable credential leak: %q is declared nullable and was accepted as null on %s.", fieldName, ref.Path),
				fmt.Sprintf("status=%d body=%s", resp.StatusCode, truncate(resp.Body, 300)),
			)
			result.Findings = append(result.Findings, finding)
		}
	}
	result.Vulnerable = len(result.Findings) > 0
	return result, nil
}

// looksLikeCredential matches a small allowlist of names where accepting
// null is unambiguously dangerous. Keeping this narrow avoids reporting
// every nullable string field in the spec.
func looksLikeCredential(name string) bool {
	lower := strings.ToLower(name)
	switch lower {
	case "password", "passwd", "pass", "secret", "token", "api_key", "apikey", "auth_token":
		return true
	}
	return false
}

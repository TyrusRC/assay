package openapisemantic

import (
	"context"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	assayhttp "github.com/TyrusRC/assay/internal/http"
)

// detectorTool is the canonical Finding.Tool value emitted by this package.
const detectorTool = "openapisemantic-detector"

// Detector probes an OpenAPI-described service for semantic mismatches
// between the published schema and what the server actually enforces.
type Detector struct {
	client *assayhttp.Client
}

// New returns a Detector bound to the supplied HTTP client.
func New(client *assayhttp.Client) *Detector {
	return &Detector{client: client}
}

// Name returns the detector identifier used by the scanner registry.
func (d *Detector) Name() string { return "openapi-semantic" }

// Description returns a one-line summary of the detector.
func (d *Detector) Description() string {
	return "OpenAPI semantic exploits: type coercion, discriminator confusion, nullable leaks, additionalProperties bypass"
}

// DetectOptions selects the spec source and tunes request behavior.
// Exactly one of SpecJSON or SpecURL must be set.
type DetectOptions struct {
	// SpecJSON is a raw OpenAPI 3.x JSON body. Takes precedence over SpecURL.
	SpecJSON []byte
	// SpecURL is fetched via the bound client when SpecJSON is empty.
	SpecURL string
	// BaseURL overrides the server origin used to render path templates.
	// When empty, the detector uses SpecURL's origin (if any).
	BaseURL string
	// Timeout caps a single probe request. Zero defers to client default.
	Timeout time.Duration
}

// DetectionResult bundles the outcome of one probe family.
type DetectionResult struct {
	// Vulnerable is true when at least one finding was emitted.
	Vulnerable bool
	// Findings are the discovered issues (may be empty).
	Findings []*core.Finding
	// DetectionType identifies which probe family produced this result.
	DetectionType string
}

// DetectAll runs every probe family in this package and merges results.
// Each probe is independent; one failing does not short-circuit the rest.
func (d *Detector) DetectAll(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	merged := &DetectionResult{
		Findings:      []*core.Finding{},
		DetectionType: "openapi-semantic-all",
	}
	var firstErr error
	for _, probe := range []func(context.Context, DetectOptions) (*DetectionResult, error){
		d.DetectTypeCoercion,
		d.DetectDiscriminatorConfusion,
		d.DetectNullableLeak,
		d.DetectAdditionalPropertiesBypass,
	} {
		res, err := probe(ctx, opts)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		if res == nil {
			continue
		}
		merged.Findings = append(merged.Findings, res.Findings...)
	}
	merged.Vulnerable = len(merged.Findings) > 0
	return merged, firstErr
}

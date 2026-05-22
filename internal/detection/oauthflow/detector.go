package oauthflow

import (
	"context"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

// toolName is stamped on every Finding produced by this package so that
// downstream reporting / dedup can attribute the source detector.
const toolName = "oauthflow-detector"

// Detector drives an OAuth/OIDC authorization endpoint with crafted
// requests and reasons about whether the IdP honors RFC-level
// protections (state binding, exact redirect_uri match, PKCE
// enforcement, signed ID-tokens).
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new oauthflow Detector wrapping the given HTTP client.
// The client's redirect policy is preserved for callers; internally,
// each probe clones the client and disables redirect-following so the
// raw `Location` header on a 3xx is observable.
func New(client *http.Client) *Detector {
	return &Detector{client: client}
}

// WithVerbose toggles verbose logging on the detector.
func (d *Detector) WithVerbose(v bool) *Detector {
	d.verbose = v
	return d
}

// DetectOptions tunes the active OAuth-flow probes.
type DetectOptions struct {
	// ClientID is the public client identifier sent to the authorize
	// endpoint. Defaults to "assay-oauthflow-probe" when empty.
	ClientID string
	// RegisteredRedirectURI is the URI that has been pre-registered with
	// the IdP for the ClientID. The redirect_uri partial-match probe
	// derives hostile variants from this base.
	RegisteredRedirectURI string
	// AuthzURL is the full authorization endpoint URL (e.g.
	// https://idp.example.com/oauth/authorize).
	AuthzURL string
	// TokenURL is the token endpoint URL used by the PKCE downgrade and
	// alg=none probes.
	TokenURL string
	// IDToken is an optional pre-fetched id_token to feed the alg=none
	// probe. When empty, DetectIDTokenAlgNone synthesizes an unsigned
	// token and submits it for validation against TokenURL.
	IDToken string
	// Timeout caps a single probe; the detector composes a derived
	// context with this deadline.
	Timeout time.Duration
}

// DefaultOptions returns sensible defaults for an OAuth-flow audit.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		ClientID: "assay-oauthflow-probe",
		Timeout:  8 * time.Second,
	}
}

// DetectionResult bundles the findings produced by a single sub-check.
type DetectionResult struct {
	// Vulnerable is true when at least one finding was emitted.
	Vulnerable bool
	// Findings carries every issue this sub-check produced.
	Findings []*core.Finding
	// DetectionType identifies which sub-check ran (state-binding,
	// redirect-uri-matching, pkce-downgrade, id-token-alg-none).
	DetectionType string
}

// withTimeout returns a derived context honoring opts.Timeout when set.
func withTimeout(parent context.Context, opts DetectOptions) (context.Context, context.CancelFunc) {
	if opts.Timeout <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, opts.Timeout)
}

// clientID returns the configured client_id or a stable default.
func (o DetectOptions) clientID() string {
	if o.ClientID == "" {
		return "assay-oauthflow-probe"
	}
	return o.ClientID
}

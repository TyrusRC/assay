package http2advanced

import (
	"crypto/tls"
	"net"
	"net/url"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

// defaultTimeout is applied when DetectOptions.Timeout is zero. Each probe
// is capped independently so a single misbehaving target cannot stall the
// caller.
const defaultTimeout = 5 * time.Second

// settingsFloodCount is the number of SETTINGS frames we emit during the
// flood probe. >100 in <1s is the abuse threshold cited in the spec; we
// send 150 to leave headroom for slow loopback servers.
const settingsFloodCount = 150

// settingsFloodWindow is the upper bound on how long the flood may take
// before we consider the server "rate-limited" by virtue of slowing the
// channel down (i.e. defensive backpressure).
const settingsFloodWindow = 1 * time.Second

// flowControlStreamCount is how many streams the flow-control probe opens
// without consuming DATA. 64 is enough to exhaust the default 64KB
// per-stream window many times over.
const flowControlStreamCount = 64

// toolName is the canonical Tool tag attached to every finding emitted by
// this package; tests and downstream aggregators key off it.
const toolName = "http2advanced-detector"

// DetectOptions configures a single probe invocation.
type DetectOptions struct {
	// Target overrides Detector.Target if non-empty. Both forms are
	// accepted because callers sometimes construct a Detector once and
	// re-target per-call.
	Target string
	// AllowDestructive must be explicitly enabled for probes that can
	// degrade the target (currently only DetectFlowControlExhaustion).
	AllowDestructive bool
	// Timeout caps the total wall-clock time spent on a single probe.
	// Zero falls back to defaultTimeout.
	Timeout time.Duration
}

// DetectionResult is the per-probe return value. Findings is empty when
// Vulnerable is false; the inverse is enforced by tests.
type DetectionResult struct {
	Vulnerable    bool
	Findings      []*core.Finding
	DetectionType string
}

// Detector probes an HTTP/2 target for frame-level abuses. The zero value
// is not useful; construct via New.
type Detector struct {
	// Target is the canonical https URL of the host under test.
	Target string
	// InsecureSkipVerify is propagated to the TLS dialer. Tests against
	// httptest.NewTLSServer require this; scanners typically pass
	// --insecure on real targets.
	InsecureSkipVerify bool
}

// New returns a Detector bound to target.
func New(target string) *Detector {
	return &Detector{Target: target}
}

// tlsConfig returns the TLS config used for the H/2 ALPN dial. Extracted
// so tests can assert the negotiated NextProtos contains "h2".
func (d *Detector) tlsConfig(serverName string) *tls.Config {
	return &tls.Config{
		ServerName:         serverName,
		NextProtos:         []string{"h2"},
		InsecureSkipVerify: d.InsecureSkipVerify, //nolint:gosec // by design, opt-in via Detector field
		MinVersion:         tls.VersionTLS12,
	}
}

// resolveTarget normalises whichever target the caller passed (opts wins
// over d.Target) into a *url.URL plus host:port string. Returns ok=false
// for non-https / unparseable inputs, which the caller treats as a no-op.
func (d *Detector) resolveTarget(opts DetectOptions) (*url.URL, string, bool) {
	raw := opts.Target
	if raw == "" {
		raw = d.Target
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Scheme != "https" || u.Host == "" {
		return nil, "", false
	}
	host := u.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = u.Host + ":443"
	}
	return u, host, true
}

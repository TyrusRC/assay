package http2advanced

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/net/http2"

	"github.com/TyrusRC/assay/internal/core"
)

// writeOversizeSettings emits a single SETTINGS frame stuffed with 1024
// repeated parameters. Returns false if the server cut us off mid-write
// (defensive behaviour — caller should no-op).
func writeOversizeSettings(framer *http2.Framer) bool {
	oversize := make([]http2.Setting, 0, 1024)
	for i := 0; i < 1024; i++ {
		oversize = append(oversize, http2.Setting{
			ID:  http2.SettingHeaderTableSize,
			Val: uint32(i),
		})
	}
	return framer.WriteSettings(oversize...) == nil
}

// floodSettings emits up to settingsFloodCount small SETTINGS frames as
// fast as the framer will accept them and returns (accepted, elapsed).
func floodSettings(framer *http2.Framer) (int, time.Duration) {
	start := time.Now()
	accepted := 0
	for i := 0; i < settingsFloodCount; i++ {
		if err := framer.WriteSettings(http2.Setting{
			ID:  http2.SettingInitialWindowSize,
			Val: uint32(65535 + i),
		}); err != nil {
			break
		}
		accepted++
	}
	return accepted, time.Since(start)
}

// DetectSettingsFlood emits a burst of SETTINGS frames (including one
// with an oversize parameter list) and decides whether the server applied
// any backpressure. A server that accepts the full burst within
// settingsFloodWindow without GOAWAY/RST is flagged.
func (d *Detector) DetectSettingsFlood(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	res := &DetectionResult{DetectionType: "settings-flood"}

	sess, ok := d.openH2Session(ctx, opts)
	if !ok {
		return res, nil
	}
	defer sess.close()

	if !writeOversizeSettings(sess.framer) {
		return res, nil
	}
	accepted, elapsed := floodSettings(sess.framer)

	if pollForPushbackFlood(sess.framer, 250*time.Millisecond) {
		return res, nil
	}
	if accepted < 100 || elapsed > settingsFloodWindow {
		// Implicit backpressure — server slowed or refused mid-burst.
		return res, nil
	}

	res.Vulnerable = true
	res.Findings = append(res.Findings, buildSettingsFloodFinding(sess.u.String(), sess.host, accepted, elapsed))
	return res, nil
}

// pollForPushbackFlood watches for GOAWAY, ENHANCE_YOUR_CALM, or a
// connection close within deadline. true = server pushed back.
func pollForPushbackFlood(framer *http2.Framer, deadline time.Duration) bool {
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		f, err := framer.ReadFrame()
		if err != nil {
			// Connection closed counts as pushback.
			return true
		}
		switch ft := f.(type) {
		case *http2.GoAwayFrame:
			return true
		case *http2.RSTStreamFrame:
			if ft.ErrCode == http2.ErrCodeEnhanceYourCalm {
				return true
			}
		}
	}
	return false
}

// buildSettingsFloodFinding assembles the High-severity finding for an
// unrate-limited SETTINGS flood.
func buildSettingsFloodFinding(target, host string, accepted int, elapsed time.Duration) *core.Finding {
	f := core.NewFinding("HTTP/2 SETTINGS Frame Flood (Unrate-Limited)", core.SeverityHigh)
	f.URL = target
	f.Tool = toolName
	f.Confidence = core.ConfidenceMedium
	f.Description = fmt.Sprintf(
		"The server accepted %d SETTINGS frames (including one oversize SETTINGS frame with 1024 parameters) within %s without sending GOAWAY, ENHANCE_YOUR_CALM, or closing the connection. An attacker can leverage this to consume server CPU on SETTINGS parsing/ACK bookkeeping or to crash stacks that mishandle oversize parameter lists.",
		accepted, elapsed.Round(time.Millisecond),
	)
	f.Evidence = fmt.Sprintf("Host: %s\nALPN: h2 (negotiated)\nSETTINGS frames accepted: %d in %s\nOversize SETTINGS frame: 1024 parameters (accepted)\nObserved pushback: none",
		host, accepted, elapsed.Round(time.Millisecond))
	f.Remediation = "Apply per-connection rate-limiting on inbound SETTINGS frames; reject SETTINGS frames whose parameter count exceeds a small bound (e.g. 8) with PROTOCOL_ERROR; ensure runtime is patched (Go 1.21.3+, nginx 1.25.3+, Envoy 1.28+). Configure SETTINGS_MAX_HEADER_LIST_SIZE and back the SETTINGS parser with a frame-frequency limiter."
	f.WithOWASPMapping(
		[]string{"WSTG-BUSL-04"},
		[]string{"A02:2025"},
		[]string{"CWE-400", "CWE-770"},
	)
	f.APITop10 = []string{"API4:2023"}
	return f
}

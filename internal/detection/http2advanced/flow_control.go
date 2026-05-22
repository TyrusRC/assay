package http2advanced

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"golang.org/x/net/http2"

	"github.com/TyrusRC/assay/internal/core"
)

// openManyStallableStreams shrinks the initial window to 1 byte then
// opens up to flowControlStreamCount streams without ever sending
// WINDOW_UPDATE. Returns the count actually opened.
func openManyStallableStreams(framer *http2.Framer, u *url.URL) int {
	if err := framer.WriteSettings(http2.Setting{
		ID:  http2.SettingInitialWindowSize,
		Val: 1,
	}); err != nil {
		return 0
	}
	hdr := encodeHeaders(u, nil)
	streamID := uint32(1)
	opened := 0
	for i := 0; i < flowControlStreamCount; i++ {
		if err := writeRequestHeaders(framer, streamID, hdr); err != nil {
			break
		}
		opened++
		streamID += 2
	}
	return opened
}

// DetectFlowControlExhaustion is gated behind opts.AllowDestructive. When
// enabled it opens flowControlStreamCount streams without sending
// WINDOW_UPDATEs, then watches for a server that stalls every stream past
// the initial 1-byte credit — the canonical flow-control DoS pattern.
func (d *Detector) DetectFlowControlExhaustion(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	res := &DetectionResult{DetectionType: "flowcontrol-exhaustion"}

	if !opts.AllowDestructive {
		// Safety contract: never run a destructive probe implicitly.
		return res, nil
	}

	sess, ok := d.openH2Session(ctx, opts)
	if !ok {
		return res, nil
	}
	defer sess.close()

	opened := openManyStallableStreams(sess.framer, sess.u)
	if opened == 0 {
		return res, nil
	}

	// Watch for pushback. A protected server will GOAWAY, RST_STREAM
	// with FLOW_CONTROL_ERROR, or close the connection. A vulnerable
	// server just stalls — we observe by checking whether ANY DATA
	// arrives within a short window. Note: a 1-byte initial window
	// means even a "Hello" body cannot arrive without WINDOW_UPDATE.
	stalled, gotPushback := observeFlowControlBehaviour(sess.framer, 500*time.Millisecond)

	if gotPushback || !stalled {
		// Server pushed back OR delivered data anyway — not vulnerable
		// to this exact pattern.
		return res, nil
	}

	res.Vulnerable = true
	res.Findings = append(res.Findings, buildFlowControlFinding(sess.u.String(), sess.host, opened))
	return res, nil
}

// observeFlowControlBehaviour returns (stalled, gotPushback):
//   - stalled=true means we saw NO DATA frames in the window.
//   - gotPushback=true means we saw GOAWAY or RST_STREAM(FLOW_CONTROL_ERROR).
//
// A protected server should produce gotPushback=true OR deliver responses
// out of band (stalled=false). A vulnerable server produces stalled=true,
// gotPushback=false.
func observeFlowControlBehaviour(framer *http2.Framer, window time.Duration) (bool, bool) {
	end := time.Now().Add(window)
	gotData := false
	for time.Now().Before(end) {
		f, err := framer.ReadFrame()
		if err != nil {
			// Connection close = pushback in this context.
			return !gotData, true
		}
		switch ft := f.(type) {
		case *http2.GoAwayFrame:
			return !gotData, true
		case *http2.RSTStreamFrame:
			if ft.ErrCode == http2.ErrCodeFlowControl ||
				ft.ErrCode == http2.ErrCodeEnhanceYourCalm {
				return !gotData, true
			}
		case *http2.DataFrame:
			if len(ft.Data()) > 0 {
				gotData = true
			}
		}
	}
	return !gotData, false
}

// buildFlowControlFinding builds the High-severity finding for a server
// that stalls under low-window stream multiplexing.
func buildFlowControlFinding(target, host string, opened int) *core.Finding {
	f := core.NewFinding("HTTP/2 Flow-Control Window Exhaustion", core.SeverityHigh)
	f.URL = target
	f.Tool = toolName
	f.Confidence = core.ConfidenceMedium
	f.Description = fmt.Sprintf(
		"After advertising a 1-byte SETTINGS_INITIAL_WINDOW_SIZE and opening %d streams without consuming any DATA, the server delivered no DATA frames and did not RST/GOAWAY the connection within the observation window. A malicious client can hold per-connection flow-control capacity hostage indefinitely, denying service to other consumers of the connection (and, on shared front-ends, to other tenants).",
		opened,
	)
	f.Evidence = fmt.Sprintf("Host: %s\nALPN: h2\nSETTINGS_INITIAL_WINDOW_SIZE advertised: 1 byte\nStreams opened (no WINDOW_UPDATE issued): %d\nDATA frames observed in 500ms: 0\nGOAWAY / FLOW_CONTROL_ERROR observed: no",
		host, opened)
	f.Remediation = "Enforce a per-connection idle-stream timer that resets stalled streams with FLOW_CONTROL_ERROR; cap SETTINGS_MAX_CONCURRENT_STREAMS; refuse SETTINGS frames that drop INITIAL_WINDOW_SIZE below a reasonable floor (1KB+); apply runtime patches for known H/2 flow-control DoS bugs (CVE-2023-44487 family fixes typically address related vectors)."
	f.WithOWASPMapping(
		[]string{"WSTG-BUSL-04"},
		[]string{"A02:2025"},
		[]string{"CWE-400", "CWE-770"},
	)
	f.APITop10 = []string{"API4:2023"}
	return f
}

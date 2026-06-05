package h2reset

import (
	"context"
	"fmt"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"golang.org/x/net/http2"
)

// DetectMadeYouReset probes for the 2025 "MadeYouReset" HTTP/2 DoS class, a
// variant of Rapid Reset that bypasses client-RST_STREAM rate limits by making
// the *server* reset the streams. We induce server-side resets by sending a
// DATA frame on a stream we already half-closed with END_STREAM (a STREAM_CLOSED
// protocol violation the server answers with RST_STREAM). A bounded burst of
// such server-induced resets that draws no connection-level push-back
// (GOAWAY/ENHANCE_YOUR_CALM/close) indicates the server counts only client
// resets and is exposed.
//
// Opt-in: like the Rapid Reset probe, this sends a small burst (burstSize) of
// stream churn — bounded and brief, but still load a target must process.
func (d *Detector) DetectMadeYouReset(ctx context.Context, targetURL string) (*Result, error) {
	res := &Result{}

	conn, err := dialH2(ctx, targetURL, d.InsecureSkipVerify, probeTimeout)
	if err != nil || conn == nil {
		return res, nil //nolint:nilerr // no h2 / unreachable: no finding
	}
	defer conn.close()

	if maxStreams, ok := readServerSettings(conn.framer); ok && maxStreams > 0 && maxStreams < uint32(burstSize) {
		// A low concurrent-stream cap also blunts MadeYouReset. No finding.
		return res, nil
	}
	if err := conn.framer.WriteSettingsAck(); err != nil {
		return res, nil
	}

	hbuf := encodeHeaders(conn.u)
	streamID := uint32(1)
	for i := 0; i < burstSize; i++ {
		select {
		case <-ctx.Done():
			return res, nil
		default:
		}
		// Half-close the stream, then send DATA on it: the server must reset
		// the stream (STREAM_CLOSED) — a server-induced reset.
		if err := conn.framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: hbuf,
			EndStream:     true,
			EndHeaders:    true,
		}); err != nil {
			return res, nil
		}
		if err := conn.framer.WriteData(streamID, false, []byte("x")); err != nil {
			return res, nil
		}
		streamID += 2
	}

	if pollForPushback(conn.framer, 500*time.Millisecond) == pushbackProtected {
		return res, nil
	}

	res.Findings = append(res.Findings, buildMadeYouResetFinding(targetURL, conn.u.Host))
	return res, nil
}

func buildMadeYouResetFinding(targetURL, host string) *core.Finding {
	f := core.NewFinding("HTTP/2 MadeYouReset Exposure", core.SeverityMedium)
	f.URL = targetURL
	f.Tool = toolName
	f.Confidence = core.ConfidenceLow
	f.Description = fmt.Sprintf(
		"The server processed %d server-induced stream resets on one HTTP/2 connection without "+
			"connection-level push-back (no GOAWAY, ENHANCE_YOUR_CALM, or close). This is the "+
			"MadeYouReset (2025) exposure pattern: by coercing the server into resetting streams, an "+
			"attacker bypasses Rapid-Reset mitigations that only rate-limit client RST_STREAM. "+
			"Confidence is reduced because a bounded probe cannot fully model the server's limits.",
		burstSize,
	)
	f.Evidence = fmt.Sprintf("Host: %s\nALPN: h2\nInduced %d server-side resets (DATA on half-closed streams)\nObserved pushback: none",
		host, burstSize)
	f.Remediation = "Upgrade to a runtime patched for MadeYouReset and rate-limit total stream resets per " +
		"connection — both client- and server-initiated — not just client RST_STREAM."
	f.WithOWASPMapping(
		[]string{"WSTG-BUSL-04"},
		[]string{"A06:2025"},
		[]string{"CWE-770"},
	)
	f.APITop10 = []string{"API4:2023"}
	return f
}

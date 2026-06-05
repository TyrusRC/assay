package h2reset

import (
	"context"
	"fmt"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"golang.org/x/net/http2"
)

// CONTINUATION-flood probe bounds. The real attack streams unbounded
// CONTINUATION frames to exhaust memory; we send a bounded amount (enough to
// exceed typical header-size limits, far below a real flood) and only check
// whether the server enforces *any* limit before we stop.
const (
	contFrames        = 32
	contFragmentBytes = 8 * 1024 // 8 KiB per frame → ~256 KiB total, bounded
)

// DetectContinuationFlood probes whether the server limits an oversized,
// never-completed HTTP/2 header block spread across CONTINUATION frames (the
// CVE-2024 "CONTINUATION flood" class). It opens a stream with HEADERS lacking
// END_HEADERS, sends a bounded series of CONTINUATION frames (also lacking
// END_HEADERS), and watches for push-back. A server that accepts the whole
// bounded block without RST_STREAM/GOAWAY/close enforces no limit on
// in-progress header blocks and is likely susceptible.
//
// This probe is intentionally opt-in: even bounded, it sends a burst of frames
// a target must buffer. Findings are reported at reduced confidence because a
// bounded probe cannot fully distinguish a high server limit from no limit.
func (d *Detector) DetectContinuationFlood(ctx context.Context, targetURL string) (*Result, error) {
	res := &Result{}

	conn, err := dialH2(ctx, targetURL, d.InsecureSkipVerify, probeTimeout)
	if err != nil || conn == nil {
		return res, nil //nolint:nilerr // no h2 / unreachable: no finding
	}
	defer conn.close()

	_, _ = readServerSettings(conn.framer)
	if err := conn.framer.WriteSettingsAck(); err != nil {
		return res, nil
	}

	// Open the stream with an incomplete header block (END_HEADERS = false).
	if err := conn.framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: encodeHeaders(conn.u),
		EndStream:     false,
		EndHeaders:    false,
	}); err != nil {
		return res, nil
	}

	fragment := make([]byte, contFragmentBytes)
	for i := 0; i < contFrames; i++ {
		select {
		case <-ctx.Done():
			return res, nil
		default:
		}
		// Never set END_HEADERS: the block stays "in progress", which is the
		// condition a patched server is supposed to bound.
		if err := conn.framer.WriteContinuation(1, false, fragment); err != nil {
			// A write failure means the server closed/limited the connection —
			// that is the protective behavior. No finding.
			return res, nil
		}
		if pollForPushback(conn.framer, 50*time.Millisecond) == pushbackProtected {
			return res, nil
		}
	}

	if pollForPushback(conn.framer, 500*time.Millisecond) == pushbackProtected {
		return res, nil
	}

	// The deferred conn.close() tears down our dangling stream.
	res.Findings = append(res.Findings, buildContinuationFinding(targetURL, conn.u.Host))
	return res, nil
}

func buildContinuationFinding(targetURL, host string) *core.Finding {
	f := core.NewFinding("HTTP/2 CONTINUATION Flood Exposure", core.SeverityMedium)
	f.URL = targetURL
	f.Tool = toolName
	f.Confidence = core.ConfidenceLow
	f.Description = fmt.Sprintf(
		"The server accepted %d CONTINUATION frames (~%d KiB) extending a single, never-completed "+
			"HTTP/2 header block without enforcing a limit (no RST_STREAM, GOAWAY, or connection close). "+
			"That is the exposure pattern for the HTTP/2 CONTINUATION Flood class (CVE-2024-27316 and "+
			"related): an attacker can stream unbounded CONTINUATION frames to exhaust server memory/CPU. "+
			"Confidence is reduced because a bounded probe cannot distinguish a very high limit from no limit.",
		contFrames, contFrames*contFragmentBytes/1024,
	)
	f.Evidence = fmt.Sprintf("Host: %s\nALPN: h2\nSent: %d CONTINUATION frames, END_HEADERS never set\nObserved pushback: none",
		host, contFrames)
	f.Remediation = "Upgrade to a runtime that bounds in-progress header-block size across HEADERS+CONTINUATION " +
		"(see CVE-2024-27316 and per-implementation advisories) and set SETTINGS_MAX_HEADER_LIST_SIZE."
	f.WithOWASPMapping(
		[]string{"WSTG-BUSL-04"},
		[]string{"A06:2025"},
		[]string{"CWE-770"},
	)
	f.APITop10 = []string{"API4:2023"}
	return f
}

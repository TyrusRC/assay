package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/TyrusRC/assay/internal/core"
	httpx "github.com/TyrusRC/assay/internal/http"
	"github.com/TyrusRC/assay/internal/verification"
)

// runVerification re-exercises findings to confirm them, reusing the scan's
// transport settings (headers, cookies, proxy, TLS posture) so verification
// requests carry the same session as the scan that produced the findings. It
// reports a one-line summary to stderr and mutates confirmed findings in place.
func runVerification(ctx context.Context, findings core.Findings, headerMap map[string]string, sessionCookies string) {
	client := httpx.NewClient().
		WithHeaders(headerMap).
		WithCookies(sessionCookies).
		WithUserAgent(userAgent).
		WithProxy(proxy).
		WithInsecure(insecure)

	engine := verification.NewEngine(client)
	sum := engine.VerifyAll(ctx, findings)
	if sum.Attempted > 0 {
		fmt.Fprintf(os.Stderr, "[*] Verification: confirmed %d/%d findings with a reproducible proof\n",
			sum.Confirmed, sum.Attempted)
	}
}

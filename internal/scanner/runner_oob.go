package scanner

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// runOOBTests launches goroutines for OOB detection tests.
func (s *InternalScanner) runOOBTests(ctx context.Context, wg *sync.WaitGroup, findingsChan chan<- *core.Finding, result *InternalScanResult, params []core.Parameter, targetURL, method string, scanClient *http.Client) {
	if !s.config.EnableOOB {
		return
	}

	if s.waitForOOBClient(10 * time.Second) {
		if s.config.Verbose {
			fmt.Fprintf(os.Stderr, "[*] Running OOB tests...\n")
		}
		for _, param := range params {
			wg.Add(1)
			go func(p core.Parameter) {
				defer wg.Done()
				emit(ctx, findingsChan, s.testOOBWithClient(ctx, targetURL, p, method, scanClient))
			}(param)
		}
	} else {
		result.Errors = append(result.Errors, "OOB testing skipped: initialization failed or timed out")
	}
}

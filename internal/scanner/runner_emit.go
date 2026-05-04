package scanner

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
)

// emit forwards findings from a detector goroutine to the shared channel.
// The collector goroutine in InternalScanner.Scan is GUARANTEED to be
// draining findingsChan until close() runs — close happens after all
// wg.Wait() calls return, so no producer can outlive the collector. A
// ctx-guarded send was tried and reverted: it dropped already-collected
// findings on timeout, which is strictly worse than letting the buffered
// channel absorb the trailing batch.
func emit(_ context.Context, ch chan<- *core.Finding, findings []*core.Finding) {
	for _, f := range findings {
		ch <- f
	}
}

// launch schedules fn to run in its own goroutine under wg. Used by the
// URL-level runner to keep each detector dispatch a single line.
func (s *InternalScanner) launch(wg *sync.WaitGroup, fn func()) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		fn()
	}()
}

// runTemplateTests executes nuclei-compatible templates against a target.
// proxyURL, when non-empty, routes all template traffic through the given proxy.
// scanCfg, when non-nil, also forwards Headers/Cookies/UserAgent so template
// requests inherit the same authentication and Burp-Suite plumbing as native
// detectors.
func (s *InternalScanner) runTemplateTests(ctx context.Context, wg *sync.WaitGroup, findingsChan chan<- *core.Finding, target *core.Target, proxyURL string, scanCfg *Config) {
	wg.Add(1)
	go func() {
		defer wg.Done()

		if s.config.Verbose {
			fmt.Fprintf(os.Stderr, "[*] Running template scanner...\n")
		}

		tsCfg := DefaultTemplateScanConfig()
		tsCfg.Verbose = s.config.Verbose
		tsCfg.ProxyURL = proxyURL
		if scanCfg != nil {
			tsCfg.Headers = scanCfg.Headers
			tsCfg.Cookies = scanCfg.Cookies
			tsCfg.UserAgent = scanCfg.UserAgent
			tsCfg.Insecure = scanCfg.Insecure
		}

		if len(s.config.TemplatePaths) == 1 {
			tsCfg.TemplatesDir = s.config.TemplatePaths[0]
		} else {
			tsCfg.TemplatesDir = s.config.TemplatePaths[0]
			tsCfg.TemplatePaths = s.config.TemplatePaths[1:]
		}

		if len(s.config.TemplateTags) > 0 {
			tsCfg.IncludeTags = s.config.TemplateTags
		}

		ts, err := NewTemplateScanner(tsCfg)
		if err != nil {
			if s.config.Verbose {
				fmt.Fprintf(os.Stderr, "[!] Template scanner creation failed: %v\n", err)
			}
			return
		}

		tsResult, err := ts.ScanWithLoad(ctx, target)
		if err != nil {
			if s.config.Verbose {
				fmt.Fprintf(os.Stderr, "[!] Template scan error: %v\n", err)
			}
			return
		}

		emit(ctx, findingsChan, tsResult.Findings)

		if s.config.Verbose {
			fmt.Fprintf(os.Stderr, "[+] Template scanner completed: %d findings from %d/%d templates\n",
				len(tsResult.Findings), tsResult.TemplatesRun, tsResult.TemplatesLoaded)
		}
	}()
}

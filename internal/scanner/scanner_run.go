package scanner

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/TyrusRC/assay/internal/checkpoint"
	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/tools"
)

// Scan executes the scan against all targets.
func (s *Scanner) Scan(ctx context.Context) (*ScanResult, error) {
	s.mu.RLock()
	targets := s.targets
	registeredTools := s.tools
	config := s.config
	enableInternal := s.enableInternal
	internalScanner := s.internalScanner
	s.mu.RUnlock()

	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets specified")
	}

	result := &ScanResult{
		Targets:   make([]string, len(targets)),
		Findings:  make(core.Findings, 0),
		StartTime: time.Now(),
	}

	for i, t := range targets {
		result.Targets[i] = t.URL()
	}

	scanCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()

	// Collect findings and errors from all tools. Both channels are drained
	// by dedicated collector goroutines started before any producers, so a
	// burst of errors (or findings) exceeding the channel buffer cannot
	// block producer goroutines and wedge wg.Wait().
	findingsChan := make(chan *core.Finding, 100)
	errorsChan := make(chan string, 10)

	var collectWg sync.WaitGroup
	collectWg.Add(2)
	go func() {
		defer collectWg.Done()
		for f := range findingsChan {
			result.Findings = append(result.Findings, f)
		}
	}()
	go func() {
		defer collectWg.Done()
		for e := range errorsChan {
			result.Errors = append(result.Errors, e)
		}
	}()

	semaphore := make(chan struct{}, config.Concurrency)

	var wg sync.WaitGroup
	var resultMu sync.Mutex

	// Phase 1: Run internal scanner (discovery + native detection).
	if enableInternal {
		if internalScanner == nil {
			var err error
			internalConfig := DefaultInternalConfig()
			internalConfig.Verbose = config.Verbose
			internalScanner, err = NewInternalScanner(internalConfig)
			if err != nil {
				errorsChan <- fmt.Sprintf("internal-scanner: %v", err)
			}
		}

		if internalScanner != nil {
			resultMu.Lock()
			result.ToolsRun++
			resultMu.Unlock()
			wg.Add(1)

			go func() {
				defer wg.Done()

				scanTargets := expandWithCrawl(scanCtx, internalScanner, targets, config.Verbose, errorsChan)

				select {
				case semaphore <- struct{}{}:
					defer func() { <-semaphore }()
				case <-scanCtx.Done():
					return
				}

				cp, cpErr := checkpoint.Load(config.ResumePath)
				if cpErr != nil {
					errorsChan <- fmt.Sprintf("checkpoint: %v", cpErr)
					cp, _ = checkpoint.Load("")
				}
				for _, f := range cp.Findings {
					findingsChan <- f
				}

				for _, target := range scanTargets {
					select {
					case <-scanCtx.Done():
						return
					default:
					}

					if cp.Done(target.URL()) {
						if config.Verbose {
							fmt.Fprintf(os.Stderr, "[*] resume: skipping already-scanned %s\n", target.URL())
						}
						continue
					}

					internalResult, err := internalScanner.Scan(scanCtx, target, config)
					if err != nil {
						errorsChan <- fmt.Sprintf("internal-scanner: %v", err)
						continue
					}

					for _, finding := range internalResult.Findings {
						findingsChan <- finding
					}

					if config.CheckpointPath != "" {
						if err := cp.Record(config.CheckpointPath, target.URL(), internalResult.Findings); err != nil {
							errorsChan <- fmt.Sprintf("checkpoint: %v", err)
						}
					}

					if internalResult.Technologies != nil && internalScanner.techDetector != nil {
						for _, tech := range internalResult.Technologies.Technologies {
							implications := internalScanner.techDetector.GetSecurityImplications(tech.Name)
							if len(implications.CommonVulnerabilities) > 0 {
								finding := core.NewFinding(
									fmt.Sprintf("Technology Detected: %s", tech.Name),
									core.SeverityInfo,
								)
								finding.URL = target.URL()
								finding.Description = fmt.Sprintf("%s detected. Potential vulnerabilities: %s",
									tech.String(), strings.Join(implications.CommonVulnerabilities[:min(3, len(implications.CommonVulnerabilities))], ", "))
								finding.Tool = "techstack-detector"
								findingsChan <- finding
							}
						}
					}
				}
			}()
		}
	}

	// Phase 2: Smart dispatch — use discovery results to select the right
	// external tools for each target, instead of running all tools blindly.
	registry := tools.NewRegistry(registeredTools)
	dispatcher := tools.NewDispatcher(registry, config.Verbose)

	for _, target := range targets {
		select {
		case <-scanCtx.Done():
			goto waitDone
		default:
		}

		baseReq := tools.NewToolRequest(target.URL()).
			WithTimeout(config.Timeout).
			WithMethod(config.Method).
			WithHeaders(config.Headers)

		if config.Cookies != "" {
			baseReq.WithCookies(config.Cookies)
		}
		if config.Data != "" {
			baseReq.WithData(config.Data)
		}
		if config.ProxyURL != "" {
			baseReq.WithProxy(config.ProxyURL)
		}
		if config.OutputDir != "" {
			baseReq.OutputDir = config.OutputDir
		}

		scanContext := s.buildScanContext(target)
		tasks := dispatcher.Dispatch(baseReq, scanContext)

		for _, task := range tasks {
			resultMu.Lock()
			result.ToolsRun++
			resultMu.Unlock()
			wg.Add(1)

			go func(tt tools.ToolTask) {
				defer wg.Done()

				select {
				case semaphore <- struct{}{}:
					defer func() { <-semaphore }()
				case <-scanCtx.Done():
					return
				}

				toolResult, err := tt.Tool.Execute(scanCtx, tt.Request)
				if err != nil {
					errorsChan <- fmt.Sprintf("%s: %v", tt.Tool.Name(), err)
					return
				}

				for _, finding := range toolResult.Findings {
					findingsChan <- finding
				}
			}(task)
		}
	}
waitDone:

	wg.Wait()
	close(findingsChan)
	close(errorsChan)
	collectWg.Wait()

	result.Findings = result.Findings.Deduplicate()
	result.Findings.SortBySeverity()

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	return result, nil
}

// buildScanContext creates a ScanContext from the internal scanner's
// discovery results for a target. External tools use this to focus on
// the right endpoints and parameters.
func (s *Scanner) buildScanContext(target *core.Target) *tools.ScanContext {
	s.mu.RLock()
	internal := s.internalScanner
	s.mu.RUnlock()

	if internal == nil {
		return nil
	}

	ctx := &tools.ScanContext{}

	if internal.techDetector != nil {
		for _, tech := range internal.Technologies {
			ctx.Technologies = append(ctx.Technologies, tech)
			lower := strings.ToLower(tech)
			if strings.Contains(lower, "wordpress") {
				ctx.IsWordPress = true
			}
			if strings.Contains(lower, "graphql") {
				ctx.HasGraphQL = true
			}
			if strings.Contains(lower, "nginx") || strings.Contains(lower, "apache") || strings.Contains(lower, "iis") {
				ctx.ServerSoftware = tech
			}
		}
	}

	if internal.discoveredURLs != nil {
		ctx.DiscoveredURLs = internal.discoveredURLs
	}

	if internal.injectionCandidates != nil {
		for _, c := range internal.injectionCandidates {
			ctx.InjectionCandidates = append(ctx.InjectionCandidates, tools.InjectionCandidate{
				URL:       c.URL,
				Parameter: c.Parameter,
				Method:    c.Method,
				Location:  c.Location,
				VulnClass: c.VulnClass,
				Evidence:  c.Evidence,
			})
		}
	}

	return ctx
}

package scanner

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/tools"
)

// Config holds scanner configuration.
type Config struct {
	// Execution settings
	Timeout     time.Duration
	Concurrency int
	Verbose     bool

	// Request settings
	Headers   map[string]string
	Cookies   string
	Data      string
	Method    string
	UserAgent string

	// Network settings
	ProxyURL string
	Insecure bool

	// Output settings
	OutputDir string
}

// DefaultConfig returns the default scanner configuration.
func DefaultConfig() *Config {
	return &Config{
		Timeout:     30 * time.Minute,
		Concurrency: 3,
		Verbose:     false,
		Method:      "GET",
		Headers:     make(map[string]string),
	}
}

// ScanSummary contains aggregated scan statistics.
type ScanSummary struct {
	TotalFindings int
	Critical      int
	High          int
	Medium        int
	Low           int
	Info          int
}

// ScanResult contains the results of a scan.
type ScanResult struct {
	Targets      []string      `json:"targets"`
	Findings     core.Findings `json:"findings"`
	Technologies []string      `json:"technologies,omitempty"`
	ToolsRun     int           `json:"tools_run"`
	ToolsSkipped int           `json:"tools_skipped"`
	StartTime    time.Time     `json:"start_time"`
	EndTime      time.Time     `json:"end_time"`
	Duration     time.Duration `json:"duration"`
	Errors       []string      `json:"errors,omitempty"`
}

// Summary returns aggregated statistics for the scan.
func (r *ScanResult) Summary() ScanSummary {
	counts := r.Findings.CountBySeverity()
	return ScanSummary{
		TotalFindings: r.Findings.Count(),
		Critical:      counts[core.SeverityCritical],
		High:          counts[core.SeverityHigh],
		Medium:        counts[core.SeverityMedium],
		Low:           counts[core.SeverityLow],
		Info:          counts[core.SeverityInfo],
	}
}

// HasCritical returns true if there are critical findings.
func (r *ScanResult) HasCritical() bool {
	for _, f := range r.Findings {
		if f.Severity == core.SeverityCritical {
			return true
		}
	}
	return false
}

// HasHighOrCritical returns true if there are high or critical findings.
func (r *ScanResult) HasHighOrCritical() bool {
	for _, f := range r.Findings {
		if f.Severity == core.SeverityCritical || f.Severity == core.SeverityHigh {
			return true
		}
	}
	return false
}

// Scanner orchestrates security scans using multiple tools.
type Scanner struct {
	targets         []*core.Target
	tools           []tools.Tool
	config          *Config
	internalScanner *InternalScanner
	enableInternal  bool
	mu              sync.RWMutex
}

// New creates a new Scanner instance.
func New() *Scanner {
	return &Scanner{
		targets:        make([]*core.Target, 0),
		tools:          make([]tools.Tool, 0),
		config:         DefaultConfig(),
		enableInternal: true, // Enable internal scanning by default
	}
}

// EnableInternalScanner enables or disables the internal scanner.
func (s *Scanner) EnableInternalScanner(enable bool) {
	s.mu.Lock()
	s.enableInternal = enable
	s.mu.Unlock()
}

// SetInternalConfig sets the internal scanner configuration.
func (s *Scanner) SetInternalConfig(config *InternalScanConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	internal, err := NewInternalScanner(config)
	if err != nil {
		return err
	}
	s.internalScanner = internal
	return nil
}

// AddTarget adds a target URL to scan.
func (s *Scanner) AddTarget(rawURL string) error {
	target, err := core.NewTarget(rawURL)
	if err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}

	s.mu.Lock()
	s.targets = append(s.targets, target)
	s.mu.Unlock()

	return nil
}

// Targets returns the list of targets.
func (s *Scanner) Targets() []*core.Target {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*core.Target, len(s.targets))
	copy(result, s.targets)
	return result
}

// RegisterTool registers a tool for scanning.
func (s *Scanner) RegisterTool(tool tools.Tool) {
	s.mu.Lock()
	s.tools = append(s.tools, tool)
	s.mu.Unlock()
}

// Tools returns the list of registered tools.
func (s *Scanner) Tools() []tools.Tool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]tools.Tool, len(s.tools))
	copy(result, s.tools)
	return result
}

// SetConfig sets the scanner configuration.
func (s *Scanner) SetConfig(config *Config) {
	s.mu.Lock()
	s.config = config
	s.mu.Unlock()
}

// Close releases resources held by the scanner, including the internal
// scanner's headless browser pool and OOB client. It is safe to call
// multiple times and safe to call on a scanner that never ran.
func (s *Scanner) Close() {
	s.mu.RLock()
	internal := s.internalScanner
	s.mu.RUnlock()

	if internal != nil {
		internal.Close()
	}
}

// Config returns the current configuration.
func (s *Scanner) Config() *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

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

	// Create context with timeout
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

	// Semaphore for concurrency limiting
	semaphore := make(chan struct{}, config.Concurrency)

	var wg sync.WaitGroup
	var resultMu sync.Mutex

	// Run internal scanner if enabled
	if enableInternal {
		// Initialize internal scanner if not already done
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

				// Acquire semaphore
				select {
				case semaphore <- struct{}{}:
					defer func() { <-semaphore }()
				case <-scanCtx.Done():
					return
				}

				for _, target := range targets {
					select {
					case <-scanCtx.Done():
						return
					default:
					}

					internalResult, err := internalScanner.Scan(scanCtx, target, config)
					if err != nil {
						errorsChan <- fmt.Sprintf("internal-scanner: %v", err)
						continue
					}

					for _, finding := range internalResult.Findings {
						findingsChan <- finding
					}

					// Add technology findings with security implications
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

	// Run each external tool
	for _, tool := range registeredTools {
		if !tool.IsAvailable() {
			resultMu.Lock()
			result.ToolsSkipped++
			resultMu.Unlock()
			continue
		}

		resultMu.Lock()
		result.ToolsRun++
		resultMu.Unlock()
		wg.Add(1)

		go func(t tools.Tool) {
			defer wg.Done()

			// Acquire semaphore
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-scanCtx.Done():
				return
			}

			for _, target := range targets {
				select {
				case <-scanCtx.Done():
					return
				default:
				}

				// Build request with all config settings
				req := tools.NewToolRequest(target.URL()).
					WithTimeout(config.Timeout).
					WithMethod(config.Method).
					WithHeaders(config.Headers)

				if config.Cookies != "" {
					req.WithCookies(config.Cookies)
				}

				if config.Data != "" {
					req.WithData(config.Data)
				}

				if config.ProxyURL != "" {
					req.WithProxy(config.ProxyURL)
				}

				if config.OutputDir != "" {
					req.OutputDir = config.OutputDir
				}

				toolResult, err := t.Execute(scanCtx, req)
				if err != nil {
					errorsChan <- fmt.Sprintf("%s: %v", t.Name(), err)
					continue
				}

				for _, finding := range toolResult.Findings {
					findingsChan <- finding
				}
			}
		}(tool)
	}

	// Wait for all producers, then close channels so collectors drain and exit.
	wg.Wait()
	close(findingsChan)
	close(errorsChan)
	collectWg.Wait()

	// Deduplicate findings
	result.Findings = result.Findings.Deduplicate()
	result.Findings.SortBySeverity()

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	return result, nil
}

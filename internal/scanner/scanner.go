package scanner

import (
	"fmt"
	"sync"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/tools"
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

	// Resume settings. CheckpointPath, when set, records scan progress per
	// target so an interrupted scan can resume. ResumePath, when set, loads a
	// prior checkpoint: already-scanned targets are skipped and their findings
	// are carried forward. They are usually the same path.
	CheckpointPath string
	ResumePath     string
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


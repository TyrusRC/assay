package scanner

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/oob"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/headless"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates/executor"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates/parser"
)

// TemplateScanner executes nuclei-compatible templates against targets.
type TemplateScanner struct {
	parser   *parser.Parser
	executor *executor.Executor
	config   *TemplateScanConfig
	mu       sync.Mutex
}

// TemplateScanConfig configures template-based scanning.
type TemplateScanConfig struct {
	// Template selection
	TemplatesDir  string
	TemplatePaths []string
	IncludeTags   []string
	ExcludeTags   []string
	Severities    []core.Severity

	// Execution settings
	Concurrency      int
	Timeout          time.Duration
	StopAtFirstMatch bool

	// Behavior
	Verbose bool

	// Variables for template interpolation
	Variables map[string]interface{}

	// ProxyURL routes all template traffic through a proxy (e.g. http://127.0.0.1:8080 for Burp Suite).
	ProxyURL string

	// Headers, Cookies, UserAgent are applied to every HTTP request the
	// template engine issues — same as for the rest of the scanner — so
	// authenticated scans and Burp-Suite proxying behave consistently
	// across native detectors and templates.
	Headers   map[string]string
	Cookies   string
	UserAgent string
	Insecure  bool

	// InteractshClient enables OOB/blind vulnerability detection via interactsh.
	InteractshClient *oob.Client

	// HeadlessPool provides browser instances for headless template steps.
	HeadlessPool *headless.Pool
}

// DefaultTemplateScanConfig returns sensible defaults.
func DefaultTemplateScanConfig() *TemplateScanConfig {
	return &TemplateScanConfig{
		Concurrency:      10,
		Timeout:          10 * time.Second,
		StopAtFirstMatch: false,
		Verbose:          false,
		Variables:        make(map[string]interface{}),
	}
}

// NewTemplateScanner creates a new template scanner.
func NewTemplateScanner(config *TemplateScanConfig) (*TemplateScanner, error) {
	if config == nil {
		config = DefaultTemplateScanConfig()
	}

	execConfig := &executor.Config{
		MaxConcurrency:   config.Concurrency,
		Timeout:          config.Timeout,
		FollowRedirects:  true,
		MaxRedirects:     10,
		StopAtFirstMatch: config.StopAtFirstMatch,
		Verbose:          config.Verbose,
		Variables:        config.Variables,
		ProxyURL:         config.ProxyURL,
		Headers:          config.Headers,
		Cookies:          config.Cookies,
		UserAgent:        config.UserAgent,
		Insecure:         config.Insecure,
	}

	execConfig.InteractshClient = config.InteractshClient
	execConfig.HeadlessPool = config.HeadlessPool

	return &TemplateScanner{
		parser:   parser.New(),
		executor: executor.New(execConfig),
		config:   config,
	}, nil
}

// LoadTemplates loads templates from configured sources.
func (s *TemplateScanner) LoadTemplates() ([]*templates.Template, error) {
	var allTemplates []*templates.Template

	// Load from directory
	if s.config.TemplatesDir != "" {
		tmpls, err := s.parser.ParseDirectory(s.config.TemplatesDir)
		if err != nil {
			return nil, fmt.Errorf("failed to load templates from directory: %w", err)
		}
		allTemplates = append(allTemplates, tmpls...)
	}

	// Load individual template files
	for _, path := range s.config.TemplatePaths {
		tmpl, err := s.parser.ParseFile(path)
		if err != nil {
			if s.config.Verbose {
				fmt.Fprintf(os.Stderr, "[!] Failed to load template %s: %v\n", path, err)
			}
			continue
		}
		allTemplates = append(allTemplates, tmpl)
	}

	// Filter by tags
	if len(s.config.IncludeTags) > 0 || len(s.config.ExcludeTags) > 0 {
		allTemplates = parser.FilterTemplatesByTags(allTemplates, s.config.IncludeTags, s.config.ExcludeTags)
	}

	// Filter by severity
	if len(s.config.Severities) > 0 {
		allTemplates = parser.FilterTemplatesBySeverity(allTemplates, s.config.Severities)
	}

	return allTemplates, nil
}

// TemplateScanResult contains results from template scanning.
type TemplateScanResult struct {
	Findings        core.Findings
	TemplatesLoaded int
	TemplatesRun    int
	Errors          []string
}

// Scan executes loaded templates against a target.
func (s *TemplateScanner) Scan(ctx context.Context, target *core.Target, tmpls []*templates.Template) (*TemplateScanResult, error) {
	result := &TemplateScanResult{
		Findings:        make(core.Findings, 0),
		TemplatesLoaded: len(tmpls),
	}

	if len(tmpls) == 0 {
		result.Errors = append(result.Errors, "no templates loaded")
		return result, nil
	}

	targetURL := target.URL()

	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Template scanner starting for: %s (%d templates)\n", targetURL, len(tmpls))
	}

	var wg sync.WaitGroup
	findingsChan := make(chan *core.Finding, 100)
	semaphore := make(chan struct{}, s.config.Concurrency)

	// Execute templates concurrently
templateLoop:
	for _, tmpl := range tmpls {
		select {
		case <-ctx.Done():
			break templateLoop
		default:
		}

		wg.Add(1)
		go func(t *templates.Template) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			s.mu.Lock()
			result.TemplatesRun++
			s.mu.Unlock()

			execResults, err := s.executor.Execute(ctx, t, targetURL)
			if err != nil {
				if s.config.Verbose {
					fmt.Fprintf(os.Stderr, "[!] Template %s error: %v\n", t.ID, err)
				}
				return
			}

			for _, execResult := range execResults {
				if execResult.Matched {
					finding := s.convertToFinding(t, execResult, targetURL)
					findingsChan <- finding
				}
			}
		}(tmpl)
	}

	// Wait for all templates to complete
	go func() {
		wg.Wait()
		close(findingsChan)
	}()

	// Collect findings
	for finding := range findingsChan {
		result.Findings = append(result.Findings, finding)
	}

	// Deduplicate
	result.Findings = result.Findings.Deduplicate()

	return result, nil
}

// ScanWithLoad loads templates and executes them against a target.
func (s *TemplateScanner) ScanWithLoad(ctx context.Context, target *core.Target) (*TemplateScanResult, error) {
	tmpls, err := s.LoadTemplates()
	if err != nil {
		return nil, err
	}

	return s.Scan(ctx, target, tmpls)
}

// convertToFinding converts a template execution result to a core finding.
func (s *TemplateScanner) convertToFinding(tmpl *templates.Template, result *templates.ExecutionResult, targetURL string) *core.Finding {
	finding := core.NewFinding(tmpl.Info.Name, tmpl.Info.Severity)
	finding.URL = targetURL
	finding.Description = tmpl.Info.Description
	if finding.Description == "" {
		finding.Description = fmt.Sprintf("Template %s matched at %s", tmpl.ID, result.MatchedAt)
	}
	finding.Tool = "template-scanner:" + tmpl.ID

	// Add evidence
	if result.Response != "" {
		finding.Evidence = result.Response
	}

	// Add remediation
	if tmpl.Info.Remediation != "" {
		finding.Remediation = tmpl.Info.Remediation
	}

	// Add extracted data to evidence
	if len(result.ExtractedData) > 0 {
		for name, values := range result.ExtractedData {
			finding.Evidence += fmt.Sprintf("\n%s: %v", name, values)
		}
	}

	// Map OWASP if classification available
	if tmpl.Info.Classification.CWEID != "" {
		finding.CWE = []string{tmpl.Info.Classification.CWEID}
	}
	if len(tmpl.Info.Classification.OWASP) > 0 {
		finding.Top10 = tmpl.Info.Classification.OWASP
	}

	// Add references
	refs := tmpl.Info.GetReferences()
	if len(refs) > 0 {
		finding.Description += "\n\nReferences:\n"
		for _, ref := range refs {
			finding.Description += "- " + ref + "\n"
		}
	}

	return finding
}

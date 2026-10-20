// Package executor provides template execution capabilities.
package executor

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/TyrusRC/assay/internal/detection/oob"
	"github.com/TyrusRC/assay/internal/headless"
	"github.com/TyrusRC/assay/internal/http"
	"github.com/TyrusRC/assay/internal/templates"
	"github.com/TyrusRC/assay/internal/templates/matchers"
)

// Executor executes nuclei-compatible templates against targets.
type Executor struct {
	client            *http.Client
	matcherEngine     *matchers.MatcherEngine
	dslEngine         *matchers.DSLEngine
	config            *Config
	dnsExecutor       *DNSExecutor
	networkExecutor   *NetworkExecutor
	sslExecutor       *SSLExecutor
	websocketExecutor *WebSocketExecutor
	whoisExecutor     *WHOISExecutor
	fileExecutor      *FileExecutor
	headlessExecutor  *HeadlessExecutor
	session           *Session
	interactshHelper  *InteractshHelper
}

// Config configures executor behavior.
type Config struct {
	// Concurrency limits
	MaxConcurrency int

	// Request settings
	Timeout         time.Duration
	FollowRedirects bool
	MaxRedirects    int

	// Behavior
	StopAtFirstMatch bool
	Verbose          bool

	// Variables for template interpolation
	Variables map[string]interface{}

	// ProxyURL routes all HTTP and protocol traffic through a proxy (e.g. http://127.0.0.1:8080 for Burp Suite).
	ProxyURL string

	// Headers, Cookies, UserAgent apply to every template HTTP request,
	// matching the behavior of the native detectors so Burp-Suite
	// proxying and authenticated scans work consistently.
	Headers   map[string]string
	Cookies   string
	UserAgent string
	Insecure  bool

	// DNS configuration
	DNSConfig *DNSConfig

	// Network configuration
	NetworkConfig *NetworkConfig

	// InteractshClient enables OOB/blind vulnerability detection via interactsh.
	// When nil, placeholder values are used for interactsh template variables.
	InteractshClient *oob.Client

	// HeadlessPool provides browser instances for headless template steps.
	// When nil, headless templates will return an error.
	HeadlessPool *headless.Pool
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		MaxConcurrency:   10,
		Timeout:          10 * time.Second,
		FollowRedirects:  true,
		MaxRedirects:     10,
		StopAtFirstMatch: false,
		Verbose:          false,
		Variables:        make(map[string]interface{}),
	}
}

// New creates a new template executor.
func New(config *Config) *Executor {
	if config == nil {
		config = DefaultConfig()
	}

	client := http.NewClient().
		WithTimeout(config.Timeout).
		WithFollowRedirects(config.FollowRedirects)

	if config.ProxyURL != "" {
		client = client.WithProxy(config.ProxyURL)
	}
	if len(config.Headers) > 0 {
		client = client.WithHeaders(config.Headers)
	}
	if config.Cookies != "" {
		client = client.WithCookies(config.Cookies)
	}
	if config.UserAgent != "" {
		client = client.WithUserAgent(config.UserAgent)
	}
	if config.Insecure {
		client = client.WithInsecure(true)
	}

	// Initialize DNS executor
	dnsConfig := config.DNSConfig
	if dnsConfig == nil {
		dnsConfig = DefaultDNSConfig()
		dnsConfig.Timeout = config.Timeout
	}

	// Initialize Network executor
	networkConfig := config.NetworkConfig
	if networkConfig == nil {
		networkConfig = DefaultNetworkConfig()
		networkConfig.Timeout = config.Timeout
	}
	networkConfig.ProxyURL = config.ProxyURL

	sslConfig := DefaultSSLConfig()
	sslConfig.Timeout = config.Timeout
	sslConfig.ProxyURL = config.ProxyURL

	wsConfig := DefaultWebSocketConfig()
	wsConfig.Timeout = config.Timeout
	wsConfig.ProxyURL = config.ProxyURL

	return &Executor{
		client:            client,
		matcherEngine:     matchers.New(),
		dslEngine:         matchers.NewDSLEngine(),
		config:            config,
		dnsExecutor:       NewDNSExecutor(dnsConfig),
		networkExecutor:   NewNetworkExecutor(networkConfig),
		sslExecutor:       NewSSLExecutor(sslConfig),
		websocketExecutor: NewWebSocketExecutor(wsConfig),
		whoisExecutor:     NewWHOISExecutor(config.Timeout, config.ProxyURL),
		fileExecutor:      NewFileExecutor(),
		headlessExecutor:  NewHeadlessExecutor(config.HeadlessPool),
		session:           NewSession(),
		interactshHelper:  NewInteractshHelper(config.InteractshClient),
	}
}

// stampResult fills template metadata and target URL onto a result.
func stampResult(result *templates.ExecutionResult, tmpl *templates.Template, targetURL string) {
	result.TemplateID = tmpl.ID
	result.TemplateName = tmpl.Info.Name
	result.Severity = tmpl.Info.Severity
	result.URL = targetURL
	result.Timestamp = time.Now()
}

// hasMatch returns true if any result matched.
func hasMatch(results []*templates.ExecutionResult) bool {
	for _, r := range results {
		if r.Matched {
			return true
		}
	}
	return false
}

// Execute runs a template against a target URL.
func (e *Executor) Execute(ctx context.Context, tmpl *templates.Template, targetURL string) ([]*templates.ExecutionResult, error) {
	if tmpl.SelfContained {
		targetURL = "" // Templates provide their own URLs in paths
	}

	// Warn about unsupported protocol types so they aren't silently skipped.
	if len(tmpl.Code) > 0 && e.config.Verbose {
		fmt.Fprintf(os.Stderr, "[!] Template %s uses code protocol (not supported, skipping code blocks)\n", tmpl.ID)
	}
	if len(tmpl.Javascript) > 0 && e.config.Verbose {
		fmt.Fprintf(os.Stderr, "[!] Template %s uses javascript protocol (not supported, skipping javascript blocks)\n", tmpl.ID)
	}

	// Workflow templates: execute each step's inline protocol blocks sequentially.
	if len(tmpl.Workflows) > 0 {
		return e.executeWorkflow(ctx, tmpl, targetURL)
	}

	if tmpl.Flow != "" {
		return e.executeWithFlow(ctx, tmpl, targetURL)
	}

	results := e.executeProtocols(ctx, tmpl, targetURL)

	// Poll interactsh for OOB callbacks after all protocols have run.
	e.pollInteractsh(ctx, tmpl, targetURL, &results)

	return results, nil
}

// executeProtocols runs all protocol blocks and returns the combined results.
func (e *Executor) executeProtocols(ctx context.Context, tmpl *templates.Template, targetURL string) []*templates.ExecutionResult {
	var results []*templates.ExecutionResult
	stopFirst := e.config.StopAtFirstMatch

	// Execute HTTP requests
	for _, httpReq := range tmpl.HTTP {
		httpResults, err := e.executeHTTP(ctx, tmpl, &httpReq, targetURL)
		if err != nil && e.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] HTTP execution error: %v\n", err)
		}
		results = append(results, httpResults...)
		if (stopFirst || httpReq.StopAtFirstMatch) && hasMatch(httpResults) {
			return results
		}
	}

	// Execute DNS queries
	for i := range tmpl.DNS {
		dnsResults, err := e.executeDNS(ctx, tmpl, &tmpl.DNS[i], targetURL)
		if err != nil && e.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] DNS execution error: %v\n", err)
		}
		results = append(results, dnsResults...)
		if stopFirst && hasMatch(dnsResults) {
			return results
		}
	}

	// Execute Network probes
	for i := range tmpl.Network {
		networkResults, err := e.executeNetwork(ctx, tmpl, &tmpl.Network[i], targetURL)
		if err != nil && e.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] Network execution error: %v\n", err)
		}
		results = append(results, networkResults...)
		if stopFirst && hasMatch(networkResults) {
			return results
		}
	}

	// Execute TCP probes (alias for Network)
	for i := range tmpl.TCP {
		tcpResults, err := e.executeNetwork(ctx, tmpl, &tmpl.TCP[i], targetURL)
		if err != nil && e.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] TCP execution error: %v\n", err)
		}
		results = append(results, tcpResults...)
		if stopFirst && hasMatch(tcpResults) {
			return results
		}
	}

	// Execute SSL probes
	for i := range tmpl.SSL {
		sslResults, err := e.executeSSL(ctx, tmpl, &tmpl.SSL[i], targetURL)
		if err != nil && e.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] SSL execution error: %v\n", err)
		}
		results = append(results, sslResults...)
		if stopFirst && hasMatch(sslResults) {
			return results
		}
	}

	// Execute WebSocket probes
	for i := range tmpl.Websocket {
		wsResult, err := e.websocketExecutor.Execute(ctx, targetURL, &tmpl.Websocket[i])
		if err != nil && e.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] WebSocket execution error: %v\n", err)
		}
		if wsResult != nil {
			stampResult(wsResult, tmpl, targetURL)
			results = append(results, wsResult)
			if stopFirst && wsResult.Matched {
				return results
			}
		}
	}

	// Execute WHOIS queries
	for i := range tmpl.Whois {
		whoisResult, err := e.whoisExecutor.Execute(ctx, targetURL, &tmpl.Whois[i])
		if err != nil && e.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] WHOIS execution error: %v\n", err)
		}
		if whoisResult != nil {
			stampResult(whoisResult, tmpl, targetURL)
			results = append(results, whoisResult)
			if stopFirst && whoisResult.Matched {
				return results
			}
		}
	}

	// Execute Headless steps
	for i := range tmpl.Headless {
		headlessResult, err := e.headlessExecutor.Execute(ctx, targetURL, &tmpl.Headless[i])
		if err != nil && e.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] Headless execution error: %v\n", err)
		}
		if headlessResult != nil {
			stampResult(headlessResult, tmpl, targetURL)
			results = append(results, headlessResult)
			if stopFirst && headlessResult.Matched {
				return results
			}
		}
	}

	// Execute File probes
	for i := range tmpl.File {
		fileResults, err := e.fileExecutor.Execute(targetURL, &tmpl.File[i])
		if err != nil && e.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] File execution error: %v\n", err)
		}
		for _, fr := range fileResults {
			stampResult(fr, tmpl, targetURL)
		}
		results = append(results, fileResults...)
		if stopFirst && hasMatch(fileResults) {
			return results
		}
	}

	return results
}

// pollInteractsh checks for OOB callbacks after all protocol blocks have run.
// If an interaction is received and no result has matched yet, it creates a
// synthetic matched result so the finding is reported.
func (e *Executor) pollInteractsh(ctx context.Context, tmpl *templates.Template, targetURL string, results *[]*templates.ExecutionResult) {
	if e.interactshHelper == nil || e.interactshHelper.client == nil {
		return
	}
	if hasMatch(*results) {
		return
	}
	if e.interactshHelper.Poll(ctx) || e.interactshHelper.HasInteraction() {
		r := &templates.ExecutionResult{
			Matched:   true,
			MatchedAt: targetURL,
			Response:  "OOB interaction received via interactsh",
		}
		stampResult(r, tmpl, targetURL)
		*results = append(*results, r)
	}
}

// executeWorkflow runs a workflow template by executing each step's protocol
// blocks sequentially. When a step has matchers, its result gates whether the
// nested subtemplates execute (basic conditional branching).
func (e *Executor) executeWorkflow(ctx context.Context, tmpl *templates.Template, targetURL string) ([]*templates.ExecutionResult, error) {
	var results []*templates.ExecutionResult
	for _, step := range tmpl.Workflows {
		stepResults := e.runWorkflowStep(ctx, tmpl, step, targetURL)
		results = append(results, stepResults...)
	}
	return results, nil
}

func (e *Executor) runWorkflowStep(ctx context.Context, parent *templates.Template, step templates.WorkflowStep, targetURL string) []*templates.ExecutionResult {
	// A workflow step with a template ID references an external template.
	// Without a template registry we can only execute inline protocol blocks
	// from the parent. Steps that only carry a Template/Tags reference are
	// logged and skipped.
	if step.Template != "" && e.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Workflow step references template %q (executing parent protocols)\n", step.Template)
	}

	stepResults := e.executeProtocols(ctx, parent, targetURL)

	// If the step has matchers, evaluate them to decide if subtemplates run.
	runSubs := true
	if len(step.Matchers) > 0 {
		runSubs = hasMatch(stepResults)
	}

	if runSubs {
		for _, sub := range step.Subtemplates {
			subResults := e.runWorkflowStep(ctx, parent, sub, targetURL)
			stepResults = append(stepResults, subResults...)
		}
	}

	return stepResults
}

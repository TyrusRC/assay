// Package executor provides template execution capabilities.
package executor

import (
	"context"
	"fmt"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/detection/oob"
	"github.com/swiss-knife-for-web-security/skws/internal/headless"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/templates"
	"github.com/swiss-knife-for-web-security/skws/internal/templates/matchers"
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

	sslConfig := DefaultSSLConfig()
	sslConfig.Timeout = config.Timeout

	wsConfig := DefaultWebSocketConfig()
	wsConfig.Timeout = config.Timeout

	return &Executor{
		client:            client,
		matcherEngine:     matchers.New(),
		dslEngine:         matchers.NewDSLEngine(),
		config:            config,
		dnsExecutor:       NewDNSExecutor(dnsConfig),
		networkExecutor:   NewNetworkExecutor(networkConfig),
		sslExecutor:       NewSSLExecutor(sslConfig),
		websocketExecutor: NewWebSocketExecutor(wsConfig),
		whoisExecutor:     NewWHOISExecutor(config.Timeout),
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

	if tmpl.Flow != "" {
		return e.executeWithFlow(ctx, tmpl, targetURL)
	}

	var results []*templates.ExecutionResult
	stopFirst := e.config.StopAtFirstMatch

	// Execute HTTP requests
	for _, httpReq := range tmpl.HTTP {
		httpResults, err := e.executeHTTP(ctx, tmpl, &httpReq, targetURL)
		if err != nil && e.config.Verbose {
			fmt.Printf("[!] HTTP execution error: %v\n", err)
		}
		results = append(results, httpResults...)
		if (stopFirst || httpReq.StopAtFirstMatch) && hasMatch(httpResults) {
			return results, nil
		}
	}

	// Execute DNS queries
	for i := range tmpl.DNS {
		dnsResults, err := e.executeDNS(ctx, tmpl, &tmpl.DNS[i], targetURL)
		if err != nil && e.config.Verbose {
			fmt.Printf("[!] DNS execution error: %v\n", err)
		}
		results = append(results, dnsResults...)
		if stopFirst && hasMatch(dnsResults) {
			return results, nil
		}
	}

	// Execute Network probes
	for i := range tmpl.Network {
		networkResults, err := e.executeNetwork(ctx, tmpl, &tmpl.Network[i], targetURL)
		if err != nil && e.config.Verbose {
			fmt.Printf("[!] Network execution error: %v\n", err)
		}
		results = append(results, networkResults...)
		if stopFirst && hasMatch(networkResults) {
			return results, nil
		}
	}

	// Execute TCP probes (alias for Network)
	for i := range tmpl.TCP {
		tcpResults, err := e.executeNetwork(ctx, tmpl, &tmpl.TCP[i], targetURL)
		if err != nil && e.config.Verbose {
			fmt.Printf("[!] TCP execution error: %v\n", err)
		}
		results = append(results, tcpResults...)
		if stopFirst && hasMatch(tcpResults) {
			return results, nil
		}
	}

	// Execute SSL probes
	for i := range tmpl.SSL {
		sslResults, err := e.executeSSL(ctx, tmpl, &tmpl.SSL[i], targetURL)
		if err != nil && e.config.Verbose {
			fmt.Printf("[!] SSL execution error: %v\n", err)
		}
		results = append(results, sslResults...)
		if stopFirst && hasMatch(sslResults) {
			return results, nil
		}
	}

	// Execute WebSocket probes
	for i := range tmpl.Websocket {
		wsResult, err := e.websocketExecutor.Execute(ctx, targetURL, &tmpl.Websocket[i])
		if err != nil && e.config.Verbose {
			fmt.Printf("[!] WebSocket execution error: %v\n", err)
		}
		if wsResult != nil {
			stampResult(wsResult, tmpl, targetURL)
			results = append(results, wsResult)
			if stopFirst && wsResult.Matched {
				return results, nil
			}
		}
	}

	// Execute WHOIS queries
	for i := range tmpl.Whois {
		whoisResult, err := e.whoisExecutor.Execute(ctx, targetURL, &tmpl.Whois[i])
		if err != nil && e.config.Verbose {
			fmt.Printf("[!] WHOIS execution error: %v\n", err)
		}
		if whoisResult != nil {
			stampResult(whoisResult, tmpl, targetURL)
			results = append(results, whoisResult)
			if stopFirst && whoisResult.Matched {
				return results, nil
			}
		}
	}

	// Execute Headless steps
	for i := range tmpl.Headless {
		headlessResult, err := e.headlessExecutor.Execute(ctx, targetURL, &tmpl.Headless[i])
		if err != nil && e.config.Verbose {
			fmt.Printf("[!] Headless execution error: %v\n", err)
		}
		if headlessResult != nil {
			stampResult(headlessResult, tmpl, targetURL)
			results = append(results, headlessResult)
			if stopFirst && headlessResult.Matched {
				return results, nil
			}
		}
	}

	return results, nil
}

// executeDNS executes a DNS query from a template.
func (e *Executor) executeDNS(ctx context.Context, tmpl *templates.Template, query *templates.DNSQuery, targetURL string) ([]*templates.ExecutionResult, error) {
	dnsResult, err := e.dnsExecutor.Execute(ctx, targetURL, query)
	if err != nil {
		return nil, err
	}

	result := &templates.ExecutionResult{
		TemplateID:    tmpl.ID,
		TemplateName:  tmpl.Info.Name,
		Severity:      tmpl.Info.Severity,
		URL:           targetURL,
		Matched:       dnsResult.Matched,
		MatchedAt:     dnsResult.Query,
		ExtractedData: dnsResult.ExtractedData,
		Timestamp:     time.Now(),
		Request:       fmt.Sprintf("DNS %s %s", dnsResult.Type, dnsResult.Query),
		Response:      dnsResult.Raw,
	}

	if dnsResult.Error != nil {
		result.Error = dnsResult.Error
	}

	return []*templates.ExecutionResult{result}, nil
}

// executeNetwork executes a network probe from a template.
func (e *Executor) executeNetwork(ctx context.Context, tmpl *templates.Template, probe *templates.NetworkProbe, targetURL string) ([]*templates.ExecutionResult, error) {
	networkResult, err := e.networkExecutor.Execute(ctx, targetURL, probe)
	if err != nil {
		return nil, err
	}

	result := &templates.ExecutionResult{
		TemplateID:    tmpl.ID,
		TemplateName:  tmpl.Info.Name,
		Severity:      tmpl.Info.Severity,
		URL:           targetURL,
		Matched:       networkResult.Matched,
		MatchedAt:     fmt.Sprintf("%s:%s", networkResult.Host, networkResult.Port),
		ExtractedData: networkResult.ExtractedData,
		Timestamp:     time.Now(),
		Request:       fmt.Sprintf("TCP %s:%s", networkResult.Host, networkResult.Port),
		Response:      networkResult.Banner,
	}

	if networkResult.Error != nil {
		result.Error = networkResult.Error
	}

	return []*templates.ExecutionResult{result}, nil
}

// executeSSL executes an SSL probe from a template and wraps the result into ExecutionResult.
func (e *Executor) executeSSL(ctx context.Context, tmpl *templates.Template, probe *templates.SSLProbe, targetURL string) ([]*templates.ExecutionResult, error) {
	sslResult, err := e.sslExecutor.Execute(ctx, targetURL, probe)
	if err != nil {
		return nil, err
	}

	result := &templates.ExecutionResult{
		TemplateID:    tmpl.ID,
		TemplateName:  tmpl.Info.Name,
		Severity:      tmpl.Info.Severity,
		URL:           targetURL,
		Matched:       sslResult.Matched,
		MatchedAt:     fmt.Sprintf("%s:%s", sslResult.Host, sslResult.Port),
		ExtractedData: sslResult.ExtractedData,
		Timestamp:     time.Now(),
		Request:       fmt.Sprintf("SSL %s:%s", sslResult.Host, sslResult.Port),
		Response:      sslResult.Raw,
	}

	if sslResult.Error != nil {
		result.Error = sslResult.Error
	}

	return []*templates.ExecutionResult{result}, nil
}

// executeWithFlow executes a template using the flow field for multi-protocol orchestration.
func (e *Executor) executeWithFlow(ctx context.Context, tmpl *templates.Template, targetURL string) ([]*templates.ExecutionResult, error) {
	flowEngine := NewFlowEngine()
	steps := flowEngine.Parse(tmpl.Flow)

	var allResults []*templates.ExecutionResult
	previousMatched := false

	for _, step := range steps {
		if step.Operator != "" && !flowEngine.ShouldContinue(step.Operator, previousMatched) {
			break
		}

		var stepResults []*templates.ExecutionResult
		var err error

		switch step.Protocol {
		case "http":
			stepResults, err = e.executeFlowHTTP(ctx, tmpl, targetURL, step.Index)
		case "dns":
			stepResults, err = e.executeFlowDNS(ctx, tmpl, targetURL, step.Index)
		case "ssl":
			stepResults, err = e.executeFlowSSL(ctx, tmpl, targetURL, step.Index)
		case "headless":
			stepResults, err = e.executeFlowHeadless(ctx, tmpl, targetURL, step.Index)
		case "websocket":
			stepResults, err = e.executeFlowWebSocket(ctx, tmpl, targetURL, step.Index)
		case "whois":
			stepResults, err = e.executeFlowWHOIS(ctx, tmpl, targetURL, step.Index)
		default:
			// Unrecognised protocols return empty results
		}

		if err != nil && e.config.Verbose {
			fmt.Printf("[!] flow step %s(%d) error: %v\n", step.Protocol, step.Index, err)
		}

		allResults = append(allResults, stepResults...)
		previousMatched = hasMatch(stepResults)
	}

	return allResults, nil
}

// executeFlowHTTP executes HTTP blocks for a flow step.
// When index is 0, all blocks are executed; otherwise only the 1-based index block is executed.
func (e *Executor) executeFlowHTTP(ctx context.Context, tmpl *templates.Template, targetURL string, index int) ([]*templates.ExecutionResult, error) {
	var results []*templates.ExecutionResult

	for i := range tmpl.HTTP {
		if index > 0 && i+1 != index {
			continue
		}
		httpResults, err := e.executeHTTP(ctx, tmpl, &tmpl.HTTP[i], targetURL)
		if err != nil {
			return results, err
		}
		results = append(results, httpResults...)
	}

	return results, nil
}

// executeFlowDNS executes DNS blocks for a flow step.
// When index is 0, all blocks are executed; otherwise only the 1-based index block is executed.
func (e *Executor) executeFlowDNS(ctx context.Context, tmpl *templates.Template, targetURL string, index int) ([]*templates.ExecutionResult, error) {
	var results []*templates.ExecutionResult

	for i := range tmpl.DNS {
		if index > 0 && i+1 != index {
			continue
		}
		dnsResults, err := e.executeDNS(ctx, tmpl, &tmpl.DNS[i], targetURL)
		if err != nil {
			return results, err
		}
		results = append(results, dnsResults...)
	}

	return results, nil
}

// executeFlowSSL executes SSL blocks for a flow step.
// When index is 0, all blocks are executed; otherwise only the 1-based index block is executed.
func (e *Executor) executeFlowSSL(ctx context.Context, tmpl *templates.Template, targetURL string, index int) ([]*templates.ExecutionResult, error) {
	var results []*templates.ExecutionResult

	for i := range tmpl.SSL {
		if index > 0 && i+1 != index {
			continue
		}
		sslResults, err := e.executeSSL(ctx, tmpl, &tmpl.SSL[i], targetURL)
		if err != nil {
			return results, err
		}
		results = append(results, sslResults...)
	}

	return results, nil
}

// executeFlowHeadless executes Headless blocks for a flow step.
// When index is 0, all blocks are executed; otherwise only the 1-based index block is executed.
func (e *Executor) executeFlowHeadless(ctx context.Context, tmpl *templates.Template, targetURL string, index int) ([]*templates.ExecutionResult, error) {
	var results []*templates.ExecutionResult

	for i := range tmpl.Headless {
		if index > 0 && i+1 != index {
			continue
		}
		headlessResult, err := e.headlessExecutor.Execute(ctx, targetURL, &tmpl.Headless[i])
		if err != nil {
			return results, err
		}
		if headlessResult != nil {
			stampResult(headlessResult, tmpl, targetURL)
			results = append(results, headlessResult)
		}
	}

	return results, nil
}

// executeFlowWebSocket executes WebSocket blocks for a flow step.
// When index is 0, all blocks are executed; otherwise only the 1-based index block is executed.
func (e *Executor) executeFlowWebSocket(ctx context.Context, tmpl *templates.Template, targetURL string, index int) ([]*templates.ExecutionResult, error) {
	var results []*templates.ExecutionResult

	for i := range tmpl.Websocket {
		if index > 0 && i+1 != index {
			continue
		}
		wsResult, err := e.websocketExecutor.Execute(ctx, targetURL, &tmpl.Websocket[i])
		if err != nil {
			return results, err
		}
		if wsResult != nil {
			stampResult(wsResult, tmpl, targetURL)
			results = append(results, wsResult)
		}
	}

	return results, nil
}

// executeFlowWHOIS executes WHOIS blocks for a flow step.
// When index is 0, all blocks are executed; otherwise only the 1-based index block is executed.
func (e *Executor) executeFlowWHOIS(ctx context.Context, tmpl *templates.Template, targetURL string, index int) ([]*templates.ExecutionResult, error) {
	var results []*templates.ExecutionResult

	for i := range tmpl.Whois {
		if index > 0 && i+1 != index {
			continue
		}
		whoisResult, err := e.whoisExecutor.Execute(ctx, targetURL, &tmpl.Whois[i])
		if err != nil {
			return results, err
		}
		if whoisResult != nil {
			stampResult(whoisResult, tmpl, targetURL)
			results = append(results, whoisResult)
		}
	}

	return results, nil
}

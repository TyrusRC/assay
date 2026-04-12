// Package executor provides template execution capabilities.
package executor

import (
	"context"
	"fmt"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/http"
	"github.com/swiss-knife-for-web-security/skws/internal/templates"
	"github.com/swiss-knife-for-web-security/skws/internal/templates/matchers"
)

// Executor executes nuclei-compatible templates against targets.
type Executor struct {
	client          *http.Client
	matcherEngine   *matchers.MatcherEngine
	config          *Config
	dnsExecutor     *DNSExecutor
	networkExecutor *NetworkExecutor
	session         *Session
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

	return &Executor{
		client:          client,
		matcherEngine:   matchers.New(),
		config:          config,
		dnsExecutor:     NewDNSExecutor(dnsConfig),
		networkExecutor: NewNetworkExecutor(networkConfig),
		session:         NewSession(),
	}
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

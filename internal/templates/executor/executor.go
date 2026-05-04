// Package executor provides template execution capabilities.
package executor

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/oob"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/headless"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates/matchers"
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

	if tmpl.Flow != "" {
		return e.executeWithFlow(ctx, tmpl, targetURL)
	}

	var results []*templates.ExecutionResult
	stopFirst := e.config.StopAtFirstMatch

	// Execute HTTP requests
	for _, httpReq := range tmpl.HTTP {
		httpResults, err := e.executeHTTP(ctx, tmpl, &httpReq, targetURL)
		if err != nil && e.config.Verbose {
			fmt.Fprintf(os.Stderr,"[!] HTTP execution error: %v\n", err)
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
			fmt.Fprintf(os.Stderr,"[!] DNS execution error: %v\n", err)
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
			fmt.Fprintf(os.Stderr,"[!] Network execution error: %v\n", err)
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
			fmt.Fprintf(os.Stderr,"[!] TCP execution error: %v\n", err)
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
			fmt.Fprintf(os.Stderr,"[!] SSL execution error: %v\n", err)
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
			fmt.Fprintf(os.Stderr,"[!] WebSocket execution error: %v\n", err)
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
			fmt.Fprintf(os.Stderr,"[!] WHOIS execution error: %v\n", err)
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
			fmt.Fprintf(os.Stderr,"[!] Headless execution error: %v\n", err)
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


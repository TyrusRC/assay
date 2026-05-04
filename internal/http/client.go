package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultTimeout is the default request timeout.
const DefaultTimeout = 30 * time.Second

// MaxResponseBodySize limits response body reads to 10MB to prevent OOM.
const MaxResponseBodySize = 10 * 1024 * 1024

// Request represents an HTTP request.
type Request struct {
	Method      string
	URL         string
	Headers     map[string]string
	Body        string
	ContentType string
}

// Response represents an HTTP response.
type Response struct {
	StatusCode    int
	Status        string
	Headers       map[string]string
	Body          string
	ContentType   string
	ContentLength int64
	URL           string
	Duration      time.Duration
	// OriginalValue holds the original parameter value before payload injection.
	// Set by SendPayload for baseline comparison in detectors.
	OriginalValue string
}

// Client is an HTTP client for security testing.
type Client struct {
	httpClient      *http.Client
	headers         map[string]string
	cookies         string
	proxyURL        string
	timeout         time.Duration
	followRedirects bool
	userAgent       string
	insecure        bool
	mu              sync.Mutex
}

// NewClient creates a new HTTP client.
func NewClient() *Client {
	c := &Client{
		headers:         make(map[string]string),
		timeout:         DefaultTimeout,
		followRedirects: true,
		userAgent:       "SKWS/1.0",
	}
	c.buildHTTPClient()
	return c
}

// buildHTTPClient constructs the underlying http.Client.
func (c *Client) buildHTTPClient() {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: c.insecure,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	// Set proxy if configured
	if c.proxyURL != "" {
		proxyURL, err := url.Parse(c.proxyURL)
		if err != nil {
			// Log the error - proxy URL is invalid, will proceed without proxy
			// Invalid proxy URL, proceeding without proxy
		} else {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	c.httpClient = &http.Client{
		Transport: transport,
		Timeout:   c.timeout,
	}

	// Configure redirect policy
	if !c.followRedirects {
		c.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
}

// Clone creates a deep copy of the client, safe for concurrent modification.
// Use this when you need a client variant (e.g., different redirect policy)
// without mutating the original shared instance.
func (c *Client) Clone() *Client {
	cloned := &Client{
		headers:         make(map[string]string, len(c.headers)),
		cookies:         c.cookies,
		proxyURL:        c.proxyURL,
		timeout:         c.timeout,
		followRedirects: c.followRedirects,
		userAgent:       c.userAgent,
		insecure:        c.insecure,
	}
	for k, v := range c.headers {
		cloned.headers[k] = v
	}
	cloned.buildHTTPClient()
	return cloned
}

// WithHeaders sets default headers for all requests.
func (c *Client) WithHeaders(headers map[string]string) *Client {
	for k, v := range headers {
		c.headers[k] = v
	}
	return c
}

// WithCookies sets cookies for all requests.
func (c *Client) WithCookies(cookies string) *Client {
	c.cookies = cookies
	return c
}

// WithProxy sets the proxy URL.
func (c *Client) WithProxy(proxyURL string) *Client {
	c.proxyURL = proxyURL
	c.rebuildNeeded()
	return c
}

// WithTimeout sets the request timeout.
func (c *Client) WithTimeout(timeout time.Duration) *Client {
	c.timeout = timeout
	c.rebuildNeeded()
	return c
}

// WithFollowRedirects sets whether to follow redirects.
func (c *Client) WithFollowRedirects(follow bool) *Client {
	c.followRedirects = follow
	c.rebuildNeeded()
	return c
}

// WithUserAgent sets the User-Agent header.
func (c *Client) WithUserAgent(ua string) *Client {
	c.userAgent = ua
	return c
}

// ClientSnapshot is a read-only view of the per-scan client settings, used
// by detectors that need to mirror the same proxy/headers/cookies/UA/insecure
// plumbing on a parallel transport (e.g. raw WebSocket dials).
type ClientSnapshot struct {
	Headers   map[string]string
	Cookies   string
	UserAgent string
	ProxyURL  string
	Insecure  bool
}

// Snapshot returns a copy of the client's per-scan settings. Useful for
// detectors that don't speak HTTP through this client (e.g. WebSocket,
// raw smuggling) but still need to honor the global plumbing.
func (c *Client) Snapshot() ClientSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	hdrs := make(map[string]string, len(c.headers))
	for k, v := range c.headers {
		hdrs[k] = v
	}
	return ClientSnapshot{
		Headers:   hdrs,
		Cookies:   c.cookies,
		UserAgent: c.userAgent,
		ProxyURL:  c.proxyURL,
		Insecure:  c.insecure,
	}
}

// HasAuth reports whether this client is carrying any kind of authentication
// (Cookie or Authorization header). Detectors use it to decide whether
// "anonymous-still-works" is meaningful — without baseline auth, the
// answer is trivially yes and not worth reporting.
func (c *Client) HasAuth() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cookies != "" {
		return true
	}
	for k := range c.headers {
		if strings.EqualFold(k, "Authorization") {
			return true
		}
	}
	return false
}

// WithInsecure disables TLS certificate verification.
func (c *Client) WithInsecure(insecure bool) *Client {
	c.insecure = insecure
	c.rebuildNeeded()
	return c
}

// rebuildNeeded marks the HTTP client as needing reconstruction.
// The actual rebuild is deferred to avoid redundant rebuilds during chained calls.
func (c *Client) rebuildNeeded() {
	c.mu.Lock()
	c.httpClient = nil
	c.mu.Unlock()
}

// ensureClient builds the HTTP client if not yet built. Thread-safe.
func (c *Client) ensureClient() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.httpClient == nil {
		c.buildHTTPClient()
	}
}

// Get performs a GET request.
func (c *Client) Get(ctx context.Context, url string) (*Response, error) {
	return c.Do(ctx, &Request{
		Method: http.MethodGet,
		URL:    url,
	})
}

// Post performs a POST request with form data.
func (c *Client) Post(ctx context.Context, url, body string) (*Response, error) {
	return c.Do(ctx, &Request{
		Method:      http.MethodPost,
		URL:         url,
		Body:        body,
		ContentType: "application/x-www-form-urlencoded",
	})
}

// PostJSON performs a POST request with JSON body.
func (c *Client) PostJSON(ctx context.Context, url, jsonBody string) (*Response, error) {
	return c.Do(ctx, &Request{
		Method:      http.MethodPost,
		URL:         url,
		Body:        jsonBody,
		ContentType: "application/json",
	})
}

// Do performs an HTTP request.
func (c *Client) Do(ctx context.Context, req *Request) (*Response, error) {
	c.ensureClient()
	start := time.Now()

	// Build HTTP request
	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set default headers
	httpReq.Header.Set("User-Agent", c.userAgent)

	// Set custom headers
	for k, v := range c.headers {
		httpReq.Header.Set(k, v)
	}

	// Set request-specific headers
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// Set content type
	if req.ContentType != "" {
		httpReq.Header.Set("Content-Type", req.ContentType)
	}

	// Set cookies
	if c.cookies != "" {
		httpReq.Header.Set("Cookie", c.cookies)
	}

	// Execute request
	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer httpResp.Body.Close()

	// Read response body with size limit to prevent OOM on large responses
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, MaxResponseBodySize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Build response
	response := &Response{
		StatusCode:    httpResp.StatusCode,
		Status:        httpResp.Status,
		Headers:       make(map[string]string),
		Body:          string(body),
		ContentType:   httpResp.Header.Get("Content-Type"),
		ContentLength: httpResp.ContentLength,
		URL:           httpResp.Request.URL.String(),
		Duration:      time.Since(start),
	}

	// Copy headers (join multi-value headers with comma per RFC 7230)
	for k, vals := range httpResp.Header {
		response.Headers[k] = strings.Join(vals, ", ")
	}

	return response, nil
}

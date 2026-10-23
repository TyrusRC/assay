package http

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/scope"
)

// DefaultTimeout is the default request timeout.
const DefaultTimeout = 30 * time.Second

// ErrOutOfScope is returned by Do when a request URL is blocked by the client's
// scope policy. Callers treat it as "not tested", never as a negative result.
var ErrOutOfScope = errors.New("request blocked: out of scope")

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
	// RawHeaders preserves multi-value headers (notably Set-Cookie, where
	// comma-joining the Headers map loses the per-cookie boundary because
	// commas legally appear inside Expires= attributes).
	RawHeaders http.Header
	// OriginalValue holds the original parameter value before payload injection.
	// Set by SendPayload for baseline comparison in detectors.
	OriginalValue string
	// WAFBlocked is true when the response looks like a WAF block page.
	WAFBlocked bool
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
	scope           *scope.Scope
	throttle        *throttle
	cookieSrc       func() string
	mu              sync.Mutex

	// paramOverride, when set, makes SendPayload route through
	// SendPayloadAt so every detector transparently injects at the right
	// location (JSON body, path segment, header, XML body) without
	// changing its own signature. Set via ForParam; each Clone inherits it.
	paramOverride *core.Parameter

	// siblingParams holds other body params from the same endpoint. When
	// SendPayloadInJSON builds the JSON body, it includes these with
	// default values so endpoints that require multiple fields (e.g.
	// {"username":"PAYLOAD","password":"test"}) reach the SQL/logic layer
	// instead of returning a 400 "missing field" error.
	siblingParams []core.Parameter

	// WAF / resilience counters (atomic, safe for concurrent reads).
	wafBlocks       int32 // consecutive WAF-block responses
	connErrors      int32 // consecutive connection-level failures
	lockoutDetected int32 // 1 when account lockout is suspected

	// wafWarnOnce ensures the WAF-block stderr warning fires only once.
	wafWarnOnce sync.Once
}

// NewClient creates a new HTTP client.
func NewClient() *Client {
	c := &Client{
		headers:         make(map[string]string),
		timeout:         DefaultTimeout,
		followRedirects: true,
		userAgent:       "assay/1.0",
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
		MaxConnsPerHost:     20,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	// Set proxy if configured. An invalid proxy URL is surfaced as a warning
	// rather than silently ignored, so the operator knows traffic is not
	// being routed through the intended proxy (e.g. Burp Suite).
	if proxy, err := resolveProxy(c.proxyURL); err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v; proceeding without proxy\n", err)
	} else if proxy != nil {
		transport.Proxy = http.ProxyURL(proxy)
	}

	c.httpClient = &http.Client{
		Transport: transport,
		Timeout:   c.timeout,
	}

	// Configure redirect policy. The closure snapshots c.followRedirects and
	// c.scope under the lock at redirect time, so a scope attached later via
	// WithScope takes effect without rebuilding the client. An out-of-scope
	// redirect is not followed (the 3xx response is returned).
	c.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		c.mu.Lock()
		follow := c.followRedirects
		sc := c.scope
		c.mu.Unlock()

		if !follow {
			return http.ErrUseLastResponse
		}
		if sc != nil && !sc.InScope(req.URL.String()) {
			return http.ErrUseLastResponse
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
}

// resolveProxy parses the configured proxy URL. It returns (nil, nil) when no
// proxy is configured, and a descriptive error when the URL is malformed or
// missing a scheme/host so callers can surface it instead of silently
// proceeding without a proxy.
func resolveProxy(proxyURL string) (*url.URL, error) {
	if proxyURL == "" {
		return nil, nil
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", proxyURL, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid proxy URL %q: missing scheme or host", proxyURL)
	}
	return u, nil
}

// Clone creates a deep copy of the client, safe for concurrent modification.
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
	if c.scope != nil && !c.scope.InScope(req.URL) {
		return nil, fmt.Errorf("%w: %s", ErrOutOfScope, req.URL)
	}
	if err := c.throttle.wait(ctx); err != nil {
		return nil, err
	}
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

	// Set cookies. A live cookie source (a re-authenticating session) wins over
	// the static cookie so a mid-scan re-auth is picked up without a rebuild.
	cookie := c.cookies
	if c.cookieSrc != nil {
		if live := c.cookieSrc(); live != "" {
			cookie = live
		}
	}
	if cookie != "" {
		httpReq.Header.Set("Cookie", cookie)
	}

	// Execute request with one retry on transient failures.
	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil || (httpResp != nil && httpResp.StatusCode >= 502 && httpResp.StatusCode <= 504) {
		if httpResp != nil {
			httpResp.Body.Close()
		}
		atomic.AddInt32(&c.connErrors, 1)
		time.Sleep(1 * time.Second)
		httpReq2, cloneErr := http.NewRequestWithContext(ctx, httpReq.Method, httpReq.URL.String(), strings.NewReader(req.Body))
		if cloneErr == nil {
			for k, vals := range httpReq.Header {
				for _, v := range vals {
					httpReq2.Header.Add(k, v)
				}
			}
			httpResp, err = c.httpClient.Do(httpReq2)
		}
		if err != nil {
			n := atomic.AddInt32(&c.connErrors, 1)
			if n >= 20 {
				fmt.Fprintf(os.Stderr, "[!] Target appears down — %d consecutive connection failures\n", n)
			}
			return nil, fmt.Errorf("request failed: %w", err)
		}
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
		RawHeaders:    httpResp.Header.Clone(),
	}

	// Copy headers (join multi-value headers with comma per RFC 7230)
	for k, vals := range httpResp.Header {
		response.Headers[k] = strings.Join(vals, ", ")
	}

	// --- WAF-block detection ---
	if isWAFBlock(response) {
		response.WAFBlocked = true
		n := atomic.AddInt32(&c.wafBlocks, 1)
		if n >= 10 {
			c.wafWarnOnce.Do(func() {
				fmt.Fprintf(os.Stderr, "[!] WAF blocking detected — %d consecutive blocks; consider reducing --rate\n", n)
			})
		}
		if n >= 3 {
			time.Sleep(5 * time.Second)
		}
	} else {
		atomic.StoreInt32(&c.wafBlocks, 0)
	}

	// --- Connection-error tracking (reset on success) ---
	atomic.StoreInt32(&c.connErrors, 0)

	// --- Account-lockout detection ---
	if isLoginURL(req.URL) && isLockoutResponse(response) {
		if atomic.CompareAndSwapInt32(&c.lockoutDetected, 0, 1) {
			fmt.Fprintf(os.Stderr, "[!] Possible account lockout detected at %s\n", req.URL)
		}
	}

	return response, nil
}


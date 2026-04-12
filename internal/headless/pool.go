package headless

import (
	"context"
	"errors"
	"os/exec"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
)

// ErrBrowserUnavailable indicates Chrome/Chromium is not available.
var ErrBrowserUnavailable = errors.New("headless: chrome/chromium not available")

// PoolConfig configures the browser pool.
type PoolConfig struct {
	MaxBrowsers     int           // Maximum browser contexts (default 3)
	NavigateTimeout time.Duration // Navigation timeout (default 15s)
	ExecPath        string        // Optional Chrome binary path
	Headless        bool          // Run in headless mode (default true)
	ProxyURL        string        // Optional proxy URL
}

// DefaultPoolConfig returns a default pool configuration.
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxBrowsers:     3,
		NavigateTimeout: 15 * time.Second,
		Headless:        true,
	}
}

// Pool manages a pool of browser pages for concurrent use.
type Pool struct {
	config      PoolConfig
	allocCtx    context.Context
	allocCancel context.CancelFunc
	pages       chan *Page
	mu          sync.Mutex
	closed      bool
}

// NewPool creates a new browser context pool.
// Returns ErrBrowserUnavailable if Chrome cannot be found.
func NewPool(config PoolConfig) (*Pool, error) {
	if config.MaxBrowsers <= 0 {
		config.MaxBrowsers = 3
	}
	if config.NavigateTimeout <= 0 {
		config.NavigateTimeout = 15 * time.Second
	}

	// Check Chrome availability
	chromePath := config.ExecPath
	if chromePath != "" {
		// Verify explicit path exists
		if _, err := exec.LookPath(chromePath); err != nil {
			return nil, ErrBrowserUnavailable
		}
	} else {
		chromePath = findChrome()
		if chromePath == "" {
			return nil, ErrBrowserUnavailable
		}
	}

	// Set up allocator options
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(chromePath),
	)

	if config.Headless {
		opts = append(opts, chromedp.Headless)
	}

	if config.ProxyURL != "" {
		opts = append(opts, chromedp.ProxyServer(config.ProxyURL))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)

	pool := &Pool{
		config:      config,
		allocCtx:    allocCtx,
		allocCancel: allocCancel,
		pages:       make(chan *Page, config.MaxBrowsers),
	}

	return pool, nil
}

// Acquire gets a Page from the pool, creating one if needed.
func (p *Pool) Acquire(ctx context.Context) (*Page, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errors.New("headless: pool is closed")
	}
	p.mu.Unlock()

	// Try to get an existing page
	select {
	case page := <-p.pages:
		return page, nil
	default:
		// Create a new page
		return p.newPage(ctx)
	}
}

// Release returns a Page to the pool for reuse.
func (p *Pool) Release(page *Page) {
	if page == nil {
		return
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		page.close()
		return
	}
	p.mu.Unlock()

	// Try to return to pool, or close if full
	select {
	case p.pages <- page:
	default:
		page.close()
	}
}

// Close shuts down the pool and all browser contexts.
func (p *Pool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	p.mu.Unlock()

	// Drain and close all pages
	close(p.pages)
	for page := range p.pages {
		page.close()
	}

	p.allocCancel()
}

// newPage creates a new browser page context.
func (p *Pool) newPage(ctx context.Context) (*Page, error) {
	browserCtx, browserCancel := chromedp.NewContext(p.allocCtx)

	// Run empty task to initialize browser
	if err := chromedp.Run(browserCtx); err != nil {
		browserCancel()
		return nil, err
	}

	return &Page{
		ctx:             browserCtx,
		cancel:          browserCancel,
		navigateTimeout: p.config.NavigateTimeout,
	}, nil
}

// findChrome searches for Chrome/Chromium in common locations.
func findChrome() string {
	candidates := []string{
		"google-chrome",
		"google-chrome-stable",
		"chromium",
		"chromium-browser",
		"/usr/bin/google-chrome",
		"/usr/bin/chromium",
		"/usr/bin/chromium-browser",
		"/snap/bin/chromium",
	}

	for _, candidate := range candidates {
		if path, err := exec.LookPath(candidate); err == nil {
			return path
		}
	}
	return ""
}

// Package headless drives a real browser via Rod (https://github.com/go-rod/rod)
// for detectors that need DOM/JS execution.
//
// Backed by Rod (auto-downloads Chromium when no system binary is found),
// not chromedp — Rod is pure Go, has no Node.js runtime dependency, and
// stays actively maintained. The exported Pool/Page surface is held
// stable so storageinj and the new domdetect-style detectors compose
// across backends transparently.
package headless

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

// ErrBrowserUnavailable indicates Chrome/Chromium is not available.
var ErrBrowserUnavailable = errors.New("headless: chrome/chromium not available")

// PoolConfig configures the browser pool.
type PoolConfig struct {
	MaxBrowsers     int           // Maximum browser pages (default 3)
	NavigateTimeout time.Duration // Per-Navigate timeout (default 15s)
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

// Pool manages a fixed-size pool of browser pages backed by a single
// rod.Browser instance. Field shape is preserved across the chromedp →
// rod migration so external tests that construct Pool literally
// (TestPool_ReleaseConcurrentWithClose) keep working.
type Pool struct {
	config      PoolConfig
	browser     *rod.Browser // nil if Pool was constructed without a launch (test path)
	allocCancel context.CancelFunc
	pages       chan *Page
	mu          sync.Mutex
	closed      bool
}

// stealthScript hides the most common automation signals so basic bot
// detectors don't immediately flag the scanner. Equivalent to what
// puppeteer-extra-plugin-stealth does in JS land. Loaded into every new
// page via Page.EvalOnNewDocument.
const stealthScript = `
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
window.chrome = {runtime: {}};
Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3,4,5]});
Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
const orig = navigator.permissions && navigator.permissions.query;
if (orig) {
  navigator.permissions.query = (p) => p.name === 'notifications'
    ? Promise.resolve({state: Notification.permission})
    : orig(p);
}
`

// NewPool launches a Rod-managed browser and returns a Pool. If
// config.ExecPath points at a missing binary we fail with
// ErrBrowserUnavailable up front so callers can degrade gracefully. If
// no ExecPath is set Rod's launcher will auto-download Chromium on first
// use (cached under ~/.cache/rod), so an empty system gets a working
// browser without manual install.
func NewPool(config PoolConfig) (*Pool, error) {
	if config.MaxBrowsers <= 0 {
		config.MaxBrowsers = 3
	}
	if config.NavigateTimeout <= 0 {
		config.NavigateTimeout = 15 * time.Second
	}

	l := launcher.New().
		Headless(config.Headless).
		// Sandboxing requires a setuid helper the Linux Chromium snap
		// install often lacks; without --no-sandbox the launcher exits
		// before exposing a CDP endpoint. Safe in our context: we only
		// ever run attacker-controlled HTML against an intentionally
		// untrusted target.
		NoSandbox(true)

	if config.ExecPath != "" {
		// Honor explicit path but verify it first — launcher would
		// otherwise hang waiting for a CDP endpoint that never appears.
		if _, err := exec.LookPath(config.ExecPath); err != nil {
			if _, statErr := os.Stat(config.ExecPath); statErr != nil {
				return nil, ErrBrowserUnavailable
			}
		}
		l = l.Bin(config.ExecPath)
	} else if found := findChrome(); found != "" {
		l = l.Bin(found)
	}
	// (else: launcher auto-downloads Chromium under ~/.cache/rod)

	if config.ProxyURL != "" {
		l = l.Proxy(config.ProxyURL)
	}

	controlURL, err := l.Launch()
	if err != nil {
		return nil, ErrBrowserUnavailable
	}

	browser := rod.New().ControlURL(controlURL)
	if err := browser.Connect(); err != nil {
		l.Cleanup()
		return nil, ErrBrowserUnavailable
	}

	return &Pool{
		config:      config,
		browser:     browser,
		allocCancel: func() { browser.MustClose(); l.Cleanup() },
		pages:       make(chan *Page, config.MaxBrowsers),
	}, nil
}

// Acquire returns a Page from the pool, creating one on demand.
func (p *Pool) Acquire(ctx context.Context) (*Page, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errors.New("headless: pool is closed")
	}
	p.mu.Unlock()

	select {
	case page := <-p.pages:
		return page, nil
	default:
		return p.newPage(ctx)
	}
}

// Release returns a Page to the pool for reuse. Holds the mutex across
// the closed-check AND the send so a concurrent Close() cannot close the
// pages channel between the two; the send is non-blocking, so holding
// the lock is safe.
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
	select {
	case p.pages <- page:
		p.mu.Unlock()
	default:
		p.mu.Unlock()
		page.close()
	}
}

// Close shuts down every Page and the underlying browser.
func (p *Pool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	p.mu.Unlock()

	close(p.pages)
	for page := range p.pages {
		page.close()
	}

	if p.allocCancel != nil {
		p.allocCancel()
	}
}

// newPage creates a fresh Rod page, applies the stealth init script, and
// wraps it in our Page type.
func (p *Pool) newPage(ctx context.Context) (*Page, error) {
	if p.browser == nil {
		return nil, errors.New("headless: pool has no browser (constructed without NewPool)")
	}
	rodPage, err := p.browser.Page(proto.TargetCreateTarget{})
	if err != nil {
		return nil, err
	}
	// Best-effort stealth — failures here aren't fatal; some Chromium
	// builds disable EvalOnNewDocument under sandbox restrictions.
	_, _ = rodPage.EvalOnNewDocument(stealthScript)

	return &Page{
		page:            rodPage,
		navigateTimeout: p.config.NavigateTimeout,
	}, nil
}

// findChrome searches for Chrome/Chromium in common locations. Returned
// path is fed to launcher.New().Bin(...) — empty means launcher will
// auto-download.
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

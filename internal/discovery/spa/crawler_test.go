package spa

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/headless"
)

// skipIfPoolUnavailable creates a headless pool or skips the test when
// no browser can be launched (matches the helper used elsewhere).
func skipIfPoolUnavailable(t *testing.T) *headless.Pool {
	t.Helper()
	pool, err := headless.NewPool(headless.DefaultPoolConfig())
	if errors.Is(err, headless.ErrBrowserUnavailable) {
		t.Skip("Skipping: headless browser unavailable")
	}
	if err != nil {
		t.Skipf("Skipping: pool init failed: %v", err)
	}
	return pool
}

// spaHandler serves a tiny SPA: the index page is JS-only (no static
// anchors). Inline JS injects two <a href="..."> elements after load
// and calls history.pushState to advertise a third route. Subpages
// just echo their path so navigation stays in-scope.
func spaHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/", "/index.html":
			fmt.Fprint(w, `<!DOCTYPE html><html><head><title>SPA</title></head>
<body>
<div id="root"></div>
<script>
(function() {
	var root = document.getElementById('root');
	var a1 = document.createElement('a');
	a1.href = '/users';
	a1.textContent = 'users';
	root.appendChild(a1);

	var a2 = document.createElement('a');
	a2.href = '/orders/42';
	a2.textContent = 'orders';
	root.appendChild(a2);

	// History API: advertise a third route.
	try { history.pushState({}, '', '/dashboard'); } catch(e) {}
})();
</script>
</body></html>`)
		default:
			fmt.Fprintf(w, "<!DOCTYPE html><html><body>%s</body></html>", r.URL.Path)
		}
	})
}

func TestNewCrawler(t *testing.T) {
	c := NewCrawler(nil)
	if c == nil {
		t.Fatal("NewCrawler returned nil")
	}
}

func TestCrawl_NilPool(t *testing.T) {
	c := NewCrawler(nil)
	_, err := c.Crawl(context.Background(), "https://example.com", CrawlOptions{})
	if err == nil {
		t.Fatal("Crawl with nil pool should error")
	}
}

func TestCrawl_SPADiscoversDynamicLinksAndPushState(t *testing.T) {
	pool := skipIfPoolUnavailable(t)
	defer pool.Close()

	ts := httptest.NewServer(spaHandler())
	defer ts.Close()

	c := NewCrawler(pool)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	urls, err := c.Crawl(ctx, ts.URL, CrawlOptions{
		MaxDepth:       0,
		MaxPages:       10,
		SameOriginOnly: true,
		WaitFor:        500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Crawl() error = %v", err)
	}

	wantSubstrings := []string{
		"/users",
		"/orders/42",
		"/dashboard",
	}
	for _, want := range wantSubstrings {
		found := false
		for _, u := range urls {
			if strings.Contains(u, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing %q in crawl results: %v", want, urls)
		}
	}
}

func TestCrawl_DeduplicatesResults(t *testing.T) {
	pool := skipIfPoolUnavailable(t)
	defer pool.Close()

	// Serve a page that injects the same link three times.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body>
<script>
for (var i=0;i<3;i++) {
	var a = document.createElement('a');
	a.href = '/same-route';
	document.body.appendChild(a);
}
</script>
</body></html>`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := NewCrawler(pool)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	urls, err := c.Crawl(ctx, ts.URL, CrawlOptions{
		SameOriginOnly: true,
		MaxPages:       5,
		WaitFor:        300 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Crawl() error = %v", err)
	}

	count := 0
	for _, u := range urls {
		if strings.HasSuffix(u, "/same-route") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected /same-route to appear once after dedup, got %d (urls=%v)", count, urls)
	}
}

func TestCrawl_SameOriginFilter(t *testing.T) {
	pool := skipIfPoolUnavailable(t)
	defer pool.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body>
<script>
var a = document.createElement('a');
a.href = 'https://other.example.com/page';
document.body.appendChild(a);
var b = document.createElement('a');
b.href = '/local';
document.body.appendChild(b);
</script>
</body></html>`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := NewCrawler(pool)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	urls, err := c.Crawl(ctx, ts.URL, CrawlOptions{
		SameOriginOnly: true,
		MaxPages:       5,
		WaitFor:        300 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Crawl() error = %v", err)
	}

	for _, u := range urls {
		if strings.Contains(u, "other.example.com") {
			t.Errorf("SameOriginOnly should have filtered cross-origin URL: %s", u)
		}
	}

	// And the local one should be present.
	foundLocal := false
	for _, u := range urls {
		if strings.HasSuffix(u, "/local") {
			foundLocal = true
		}
	}
	if !foundLocal {
		t.Errorf("local link missing from results: %v", urls)
	}
}

// TestCrawl_StableOrder is a lightweight sanity check: the output is
// deterministically sorted so callers can assert on it without flakiness.
func TestCrawl_StableOrder(t *testing.T) {
	pool := skipIfPoolUnavailable(t)
	defer pool.Close()

	ts := httptest.NewServer(spaHandler())
	defer ts.Close()

	c := NewCrawler(pool)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	urls, err := c.Crawl(ctx, ts.URL, CrawlOptions{
		SameOriginOnly: true,
		MaxPages:       5,
		WaitFor:        300 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Crawl() error = %v", err)
	}
	sorted := append([]string(nil), urls...)
	sort.Strings(sorted)
	for i := range urls {
		if urls[i] != sorted[i] {
			t.Errorf("results not sorted: index %d: got %q, want %q (full=%v)", i, urls[i], sorted[i], urls)
			break
		}
	}
}

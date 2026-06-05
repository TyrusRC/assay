package crawl

import (
	"context"
	"testing"
)

// mapFetcher serves canned HTML keyed by normalized path.
type mapFetcher struct {
	pages map[string]string
	calls int
}

func (m *mapFetcher) Fetch(_ context.Context, url string) (string, error) {
	m.calls++
	if body, ok := m.pages[normalizePath(url)]; ok {
		return body, nil
	}
	return "<html></html>", nil
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if normalizePath(s) == want {
			return true
		}
	}
	return false
}

func TestCrawl_DiscoversTransitiveEndpoints(t *testing.T) {
	f := &mapFetcher{pages: map[string]string{
		"/":         `<a href="/products">p</a><a href="/login">l</a>`,
		"/products": `<a href="/products/1">1</a><a href="/">home</a>`,
		"/products/1": `<a href="/">home</a><form action="/cart" method="post">` +
			`<input name="id"></form>`,
		"/login": `<form action="/login" method="post"><input name="u"><input name="p"></form>`,
	}}
	c := &Crawler{Fetcher: f, SameHostOnly: true}
	res := c.Crawl(context.Background(), []string{"http://app.test/"})

	for _, want := range []string{"/", "/products", "/products/1", "/login", "/cart"} {
		if !contains(res.Endpoints, want) {
			t.Errorf("expected %s among endpoints: %v", want, res.Endpoints)
		}
	}
}

func TestCrawl_DedupsEquivalentStates(t *testing.T) {
	// /a and /b are structurally identical (both only link home), so they are
	// the same state: three URLs are fetched but only two distinct states exist.
	f := &mapFetcher{pages: map[string]string{
		"/":  `<a href="/a">a</a><a href="/b">b</a>`,
		"/a": `<a href="/">home</a>`,
		"/b": `<a href="/">home</a>`,
	}}
	c := &Crawler{Fetcher: f, SameHostOnly: true}
	res := c.Crawl(context.Background(), []string{"http://app.test/"})

	if res.States != 2 {
		t.Errorf("expected 2 distinct states (root + the shared a/b state), got %d", res.States)
	}
	if !contains(res.Endpoints, "/a") || !contains(res.Endpoints, "/b") {
		t.Errorf("both equivalent URLs should still be recorded as endpoints: %v", res.Endpoints)
	}
}

func TestCrawl_SameHostOnly(t *testing.T) {
	f := &mapFetcher{pages: map[string]string{
		"/": `<a href="/in">in</a><a href="https://evil.test/out">out</a>`,
	}}
	c := &Crawler{Fetcher: f, SameHostOnly: true}
	res := c.Crawl(context.Background(), []string{"http://app.test/"})
	for _, e := range res.Endpoints {
		if normalizePath(e) == "/out" {
			t.Errorf("off-host URL should be excluded: %v", res.Endpoints)
		}
	}
}

func TestCrawl_RespectsMaxRequests(t *testing.T) {
	// A chain longer than the request budget must stop early.
	pages := map[string]string{}
	pages["/"] = `<a href="/p1">n</a>`
	for i := 1; i < 20; i++ {
		pages["/p"+itoa(i)] = `<a href="/p` + itoa(i+1) + `">n</a>`
	}
	f := &mapFetcher{pages: pages}
	c := &Crawler{Fetcher: f, SameHostOnly: true, MaxRequests: 5}
	res := c.Crawl(context.Background(), []string{"http://app.test/"})
	if res.Requests > 5 {
		t.Errorf("expected at most 5 requests, made %d", res.Requests)
	}
	if f.calls > 5 {
		t.Errorf("fetcher called %d times, budget was 5", f.calls)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

package discovery

import (
	"context"
	nethttp "net/http"
	"net/http/httptest"
	"testing"

	assayhttp "github.com/TyrusRC/assay/internal/http"
)

// With a client set, the robots discoverer fetches /robots.txt itself even when
// the scanned URL (the site root) returned HTML.
func TestRobotsSitemapDiscoverer_SelfFetch(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if r.URL.Path == "/robots.txt" {
			w.Write([]byte("User-agent: *\nDisallow: /admin/panel\n"))
			return
		}
		w.Write([]byte("<html>home</html>"))
	}))
	defer srv.Close()

	d := NewRobotsSitemapDiscoverer().WithClient(assayhttp.NewClient())
	params, err := d.Discover(context.Background(), srv.URL, &assayhttp.Response{Body: "<html>home</html>"})
	if err != nil {
		t.Fatal(err)
	}
	var sawAdmin, sawPanel bool
	for _, p := range params {
		if p.Name == "admin" {
			sawAdmin = true
		}
		if p.Name == "panel" {
			sawPanel = true
		}
	}
	if !sawAdmin || !sawPanel {
		t.Errorf("expected admin+panel path segments from fetched robots.txt, got %+v", params)
	}
}

// With a client set, the OpenAPI discoverer fetches a conventional spec path.
func TestOpenAPIDiscoverer_SelfFetch(t *testing.T) {
	spec := `{"openapi":"3.0.0","paths":{"/users/{id}":{"get":{"parameters":[{"name":"verbose","in":"query"}]}}}}`
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(spec))
			return
		}
		w.Write([]byte("<html>home</html>"))
	}))
	defer srv.Close()

	d := NewOpenAPIDiscoverer().WithClient(assayhttp.NewClient())
	params, err := d.Discover(context.Background(), srv.URL, &assayhttp.Response{Body: "<html>home</html>"})
	if err != nil {
		t.Fatal(err)
	}
	var sawID, sawVerbose bool
	for _, p := range params {
		if p.Name == "id" {
			sawID = true
		}
		if p.Name == "verbose" {
			sawVerbose = true
		}
	}
	if !sawID || !sawVerbose {
		t.Errorf("expected id+verbose params from fetched spec, got %+v", params)
	}
}

// Without a client, the discoverers keep the old behavior: parse only the handed
// response, fetch nothing.
func TestDiscoverers_NoClientNoFetch(t *testing.T) {
	r := NewRobotsSitemapDiscoverer()
	if params, _ := r.Discover(context.Background(), "https://example.com/", &assayhttp.Response{Body: ""}); len(params) != 0 {
		t.Errorf("robots without client must not fetch, got %+v", params)
	}
	o := NewOpenAPIDiscoverer()
	if params, _ := o.Discover(context.Background(), "https://example.com/", &assayhttp.Response{Body: "<html>"}); len(params) != 0 {
		t.Errorf("openapi without client must not fetch, got %+v", params)
	}
}

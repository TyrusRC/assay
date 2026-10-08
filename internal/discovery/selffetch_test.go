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

// With a client, the GraphQL discoverer POSTs an introspection query to /graphql
// and extracts field + argument names.
func TestGraphQLIntrospectionDiscoverer_SelfFetch(t *testing.T) {
	introspection := `{"data":{"__schema":{"types":[{"name":"Query","fields":[` +
		`{"name":"user","args":[{"name":"userId"}]}]}]}}}`
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if r.URL.Path == "/graphql" && r.Method == nethttp.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(introspection))
			return
		}
		w.Write([]byte("<html>home</html>"))
	}))
	defer srv.Close()

	d := NewGraphQLIntrospectionDiscoverer().WithClient(assayhttp.NewClient())
	params, err := d.Discover(context.Background(), srv.URL, &assayhttp.Response{Body: "<html>home</html>"})
	if err != nil {
		t.Fatal(err)
	}
	var sawField, sawArg bool
	for _, p := range params {
		if p.Name == "user" {
			sawField = true
		}
		if p.Name == "userId" {
			sawArg = true
		}
	}
	if !sawField || !sawArg {
		t.Errorf("expected field 'user' + arg 'userId' from introspection, got %+v", params)
	}
}

// With a client, the JSRoute discoverer fetches the page's <script src> files
// and extracts query params from URL literals inside them.
func TestJSRouteDiscoverer_SelfFetch(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if r.URL.Path == "/app.js" {
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`fetch("/api/data?token=abc&id=1");`))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><script src="/app.js"></script></head></html>`))
	}))
	defer srv.Close()

	d := NewJSRouteDiscoverer().WithClient(assayhttp.NewClient())
	page := &assayhttp.Response{
		Body:        `<html><head><script src="/app.js"></script></head></html>`,
		ContentType: "text/html",
	}
	params, err := d.Discover(context.Background(), srv.URL, page)
	if err != nil {
		t.Fatal(err)
	}
	var sawToken, sawID bool
	for _, p := range params {
		if p.Name == "token" {
			sawToken = true
		}
		if p.Name == "id" {
			sawID = true
		}
	}
	if !sawToken || !sawID {
		t.Errorf("expected token+id params from fetched script, got %+v", params)
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

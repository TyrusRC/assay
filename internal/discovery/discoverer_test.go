package discovery

import (
	"context"
	"errors"
	gohttp "net/http"
	"net/http/httptest"
	"testing"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// mockDiscoverer is a test double for the Discoverer interface.
type mockDiscoverer struct {
	name   string
	params []core.Parameter
	err    error
}

func (m *mockDiscoverer) Name() string { return m.name }
func (m *mockDiscoverer) Discover(_ context.Context, _ string, _ *http.Response) ([]core.Parameter, error) {
	return m.params, m.err
}

// newTestHTTPServer creates a minimal httptest server for pipeline tests.
func newTestHTTPServer() *httptest.Server {
	return httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		w.Write([]byte("OK"))
	}))
}

func TestNewPipeline(t *testing.T) {
	client := http.NewClient()
	p := NewPipeline(client)

	if p == nil {
		t.Fatal("NewPipeline() returned nil")
	}
	if len(p.Discoverers()) != 0 {
		t.Errorf("Discoverers() count = %d, want 0", len(p.Discoverers()))
	}
}

func TestPipeline_Register(t *testing.T) {
	p := NewPipeline(http.NewClient())
	p.Register(&mockDiscoverer{name: "test"})

	if len(p.Discoverers()) != 1 {
		t.Errorf("Discoverers() count = %d, want 1", len(p.Discoverers()))
	}
	if p.Discoverers()[0].Name() != "test" {
		t.Errorf("Discoverers()[0].Name() = %q, want %q", p.Discoverers()[0].Name(), "test")
	}
}

func TestPipeline_Run_EmptyDiscoverers(t *testing.T) {
	p := NewPipeline(http.NewClient())

	// No discoverers registered, so no HTTP request needed
	result, err := p.Run(context.Background(), "http://localhost:0")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(result.Parameters) != 0 {
		t.Errorf("Parameters count = %d, want 0", len(result.Parameters))
	}
	if len(result.Sources) != 0 {
		t.Errorf("Sources count = %d, want 0", len(result.Sources))
	}
}

func TestPipeline_Run_MockDiscoverers(t *testing.T) {
	ts := newTestHTTPServer()
	defer ts.Close()

	p := NewPipeline(http.NewClient())

	p.Register(&mockDiscoverer{
		name: "d1",
		params: []core.Parameter{
			{Name: "username", Location: core.ParamLocationBody},
			{Name: "password", Location: core.ParamLocationBody},
		},
	})
	p.Register(&mockDiscoverer{
		name: "d2",
		params: []core.Parameter{
			{Name: "session", Location: core.ParamLocationCookie},
		},
	})

	result, err := p.Run(context.Background(), ts.URL)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(result.Parameters) != 3 {
		t.Errorf("Parameters count = %d, want 3", len(result.Parameters))
	}
	if result.Sources["d1"] != 2 {
		t.Errorf("Sources[d1] = %d, want 2", result.Sources["d1"])
	}
	if result.Sources["d2"] != 1 {
		t.Errorf("Sources[d2] = %d, want 1", result.Sources["d2"])
	}
}

func TestPipeline_Run_Deduplication(t *testing.T) {
	ts := newTestHTTPServer()
	defer ts.Close()

	p := NewPipeline(http.NewClient())

	// Both discoverers find the same parameter
	p.Register(&mockDiscoverer{
		name: "d1",
		params: []core.Parameter{
			{Name: "token", Location: core.ParamLocationCookie},
		},
	})
	p.Register(&mockDiscoverer{
		name: "d2",
		params: []core.Parameter{
			{Name: "token", Location: core.ParamLocationCookie},
		},
	})

	result, err := p.Run(context.Background(), ts.URL)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(result.Parameters) != 1 {
		t.Errorf("Parameters count = %d, want 1 (should deduplicate)", len(result.Parameters))
	}
}

func TestPipeline_Run_SameNameDifferentLocation(t *testing.T) {
	ts := newTestHTTPServer()
	defer ts.Close()

	p := NewPipeline(http.NewClient())

	p.Register(&mockDiscoverer{
		name: "d1",
		params: []core.Parameter{
			{Name: "id", Location: core.ParamLocationQuery},
			{Name: "id", Location: core.ParamLocationBody},
		},
	})

	result, err := p.Run(context.Background(), ts.URL)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	// Same name but different location should NOT be deduplicated
	if len(result.Parameters) != 2 {
		t.Errorf("Parameters count = %d, want 2", len(result.Parameters))
	}
}

func TestPipeline_Run_DiscovererError(t *testing.T) {
	ts := newTestHTTPServer()
	defer ts.Close()

	p := NewPipeline(http.NewClient())

	p.Register(&mockDiscoverer{
		name: "good",
		params: []core.Parameter{
			{Name: "username", Location: core.ParamLocationBody},
		},
	})
	p.Register(&mockDiscoverer{
		name: "bad",
		err:  errors.New("parse error"),
	})

	result, err := p.Run(context.Background(), ts.URL)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	// Good discoverer's results should still be present
	if len(result.Parameters) != 1 {
		t.Errorf("Parameters count = %d, want 1", len(result.Parameters))
	}
	// Error should be recorded
	if len(result.Errors) != 1 {
		t.Errorf("Errors count = %d, want 1", len(result.Errors))
	}
}

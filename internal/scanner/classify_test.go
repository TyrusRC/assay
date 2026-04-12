package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	skwshttp "github.com/swiss-knife-for-web-security/skws/internal/http"
)

func TestClassifyParameter_ReflectedCanary(t *testing.T) {
	// Server reflects the canary value in response body
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		input := r.URL.Query().Get("name")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Hello " + input + "</body></html>"))
	}))
	defer server.Close()

	client := skwshttp.NewClient().WithTimeout(5 * time.Second)
	param := core.Parameter{
		Name:     "name",
		Location: core.ParamLocationQuery,
		Value:    "test",
	}

	ctx := context.Background()
	ClassifyParameter(ctx, client, server.URL+"?name=test", &param, "GET")

	if !param.Reflected {
		t.Error("param should be marked as Reflected when canary is reflected")
	}
	if param.ContentType == "" {
		t.Error("param ContentType should be set")
	}
	if !strings.Contains(param.ContentType, "text/html") {
		t.Errorf("param ContentType = %q, want text/html", param.ContentType)
	}
}

func TestClassifyParameter_NotReflected(t *testing.T) {
	// Server does NOT reflect the input
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	client := skwshttp.NewClient().WithTimeout(5 * time.Second)
	param := core.Parameter{
		Name:     "id",
		Location: core.ParamLocationQuery,
		Value:    "123",
	}

	ctx := context.Background()
	ClassifyParameter(ctx, client, server.URL+"?id=123", &param, "GET")

	if param.Reflected {
		t.Error("param should NOT be marked as Reflected when canary is not reflected")
	}
	if !strings.Contains(param.ContentType, "application/json") {
		t.Errorf("param ContentType = %q, want application/json", param.ContentType)
	}
}

func TestClassifyParameter_SetsClassification(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := skwshttp.NewClient().WithTimeout(5 * time.Second)
	ctx := context.Background()

	tests := []struct {
		name           string
		paramName      string
		wantClassification string
	}{
		{"id param", "id", core.ParamClassID},
		{"file param", "file", core.ParamClassFile},
		{"url param", "url", core.ParamClassURL},
		{"search param", "search", core.ParamClassSearch},
		{"cmd param", "cmd", core.ParamClassCommand},
		{"template param", "template", core.ParamClassTemplate},
		{"random param", "foobar", core.ParamClassGeneric},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			param := core.Parameter{
				Name:     tt.paramName,
				Location: core.ParamLocationQuery,
				Value:    "test",
			}
			ClassifyParameter(ctx, client, server.URL+"?"+tt.paramName+"=test", &param, "GET")

			if param.Classification != tt.wantClassification {
				t.Errorf("Classification = %q, want %q", param.Classification, tt.wantClassification)
			}
		})
	}
}

func TestClassifyParameter_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := skwshttp.NewClient().WithTimeout(5 * time.Second)
	param := core.Parameter{
		Name:     "id",
		Location: core.ParamLocationQuery,
		Value:    "1",
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Should not panic, just set classification from name heuristics
	ClassifyParameter(ctx, client, server.URL+"?id=1", &param, "GET")

	// Classification should still be set from heuristics even if requests fail
	if param.Classification == "" {
		t.Error("Classification should be set even when context is cancelled")
	}
}

func TestClassifyParameters_Batch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		input := r.URL.Query().Get("q")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Search: " + input))
	}))
	defer server.Close()

	client := skwshttp.NewClient().WithTimeout(5 * time.Second)
	params := []core.Parameter{
		{Name: "q", Location: core.ParamLocationQuery, Value: "test"},
		{Name: "page", Location: core.ParamLocationQuery, Value: "1"},
	}

	ctx := context.Background()
	ClassifyParameters(ctx, client, server.URL+"?q=test&page=1", params, "GET")

	for _, p := range params {
		if p.Classification == "" {
			t.Errorf("param %q should have Classification set", p.Name)
		}
	}
}

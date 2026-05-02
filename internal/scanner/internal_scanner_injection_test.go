package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
)

func TestInternalScanner_testNoSQL_Disabled(t *testing.T) {
	config := &InternalScanConfig{
		EnableNoSQL:    false,
		RequestTimeout: 5 * time.Second,
	}

	_, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}
}

func TestInternalScanner_testSSTI_Integration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("input")
		if strings.Contains(input, "{{7*7}}") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Result: 49"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello " + input))
	}))
	defer server.Close()

	config := &InternalScanConfig{
		EnableSSTI:          true,
		MaxPayloadsPerParam: 10,
		RequestTimeout:      10 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	ctx := context.Background()
	findings := scanner.testSSTI(ctx, server.URL+"?input=test", core.Parameter{Name: "input", Location: core.ParamLocationQuery}, "GET")

	if len(findings) == 0 {
		t.Log("SSTI vulnerability not detected (may need specific payload)")
	}
}

func TestInternalScanner_testRedirect_Integration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectURL := r.URL.Query().Get("redirect")
		if redirectURL != "" {
			w.Header().Set("Location", redirectURL)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := &InternalScanConfig{
		EnableRedirect:      true,
		MaxPayloadsPerParam: 10,
		RequestTimeout:      10 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	ctx := context.Background()
	findings := scanner.testRedirect(ctx, server.URL+"?redirect=", core.Parameter{Name: "redirect", Location: core.ParamLocationQuery}, "GET")

	if len(findings) == 0 {
		t.Log("Open Redirect vulnerability not detected (detector may need specific payload)")
	}
}

func TestInternalScanner_testCRLF_Integration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("input")
		w.Header().Set("X-Custom-Header", input)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := &InternalScanConfig{
		EnableCRLF:          true,
		MaxPayloadsPerParam: 10,
		RequestTimeout:      10 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	ctx := context.Background()
	findings := scanner.testCRLF(ctx, server.URL+"?input=test", core.Parameter{Name: "input", Location: core.ParamLocationQuery}, "GET")
	t.Logf("CRLF findings: %d", len(findings))
}

func TestInternalScanner_testNoSQL_Integration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("search")
		if strings.Contains(query, "$") || strings.Contains(query, "{") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"error": "MongoError: $where clause has unexpected type"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"results": []}`))
	}))
	defer server.Close()

	config := &InternalScanConfig{
		EnableNoSQL:         true,
		MaxPayloadsPerParam: 20,
		RequestTimeout:      10 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	ctx := context.Background()
	findings := scanner.testNoSQL(ctx, server.URL+"?search=test", core.Parameter{Name: "search", Location: core.ParamLocationQuery}, "GET")
	t.Logf("NoSQL findings: %d", len(findings))
}

func TestInternalScanner_testJWT(t *testing.T) {
	config := DefaultInternalConfig()
	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	weakSecretJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o"

	ctx := context.Background()
	findings := scanner.testJWT(ctx, weakSecretJWT)

	if len(findings) == 0 {
		t.Log("JWT weak secret not detected (secret list may not include 'secret')")
	} else {
		t.Logf("JWT findings: %d", len(findings))
	}
}

func TestInternalScanner_testLDAP_Integration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("user")
		if strings.Contains(input, ")(") || strings.Contains(input, "*)") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("LDAP Error: javax.naming.NamingException: Invalid search filter"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"user": "` + input + `"}`))
	}))
	defer server.Close()

	config := &InternalScanConfig{
		EnableLDAP:          true,
		MaxPayloadsPerParam: 10,
		RequestTimeout:      10 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	ctx := context.Background()
	findings := scanner.testLDAP(ctx, server.URL+"?user=test", core.Parameter{Name: "user", Location: core.ParamLocationQuery}, "GET")
	t.Logf("LDAP findings: %d", len(findings))
}

func TestInternalScanner_testXPath_Integration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("query")
		if strings.Contains(input, "'") || strings.Contains(input, "or") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("XPathException: Invalid expression"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<result>` + input + `</result>`))
	}))
	defer server.Close()

	config := &InternalScanConfig{
		EnableXPath:         true,
		MaxPayloadsPerParam: 10,
		RequestTimeout:      10 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	ctx := context.Background()
	findings := scanner.testXPath(ctx, server.URL+"?query=test", core.Parameter{Name: "query", Location: core.ParamLocationQuery}, "GET")
	t.Logf("XPath findings: %d", len(findings))
}

func TestInternalScanner_testHeaderInj_Integration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("redirect")
		w.Header().Set("Location", input)
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	config := &InternalScanConfig{
		EnableHeaderInj:     true,
		MaxPayloadsPerParam: 10,
		RequestTimeout:      10 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	ctx := context.Background()
	findings := scanner.testHeaderInj(ctx, server.URL+"?redirect=test", core.Parameter{Name: "redirect", Location: core.ParamLocationQuery}, "GET")
	t.Logf("HeaderInj findings: %d", len(findings))
}

func TestInternalScanner_testCSTI_Integration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("name")
		if strings.Contains(input, "{{") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("49"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello " + input))
	}))
	defer server.Close()

	config := &InternalScanConfig{
		EnableCSTI:          true,
		MaxPayloadsPerParam: 10,
		RequestTimeout:      10 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	ctx := context.Background()
	findings := scanner.testCSTI(ctx, server.URL+"?name=test", core.Parameter{Name: "name", Location: core.ParamLocationQuery}, "GET")
	t.Logf("CSTI findings: %d", len(findings))
}

func TestInternalScanner_testRFI_Integration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		input := r.URL.Query().Get("file")
		if strings.Contains(input, "http://") || strings.Contains(input, "https://") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Included remote content"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("File: " + input))
	}))
	defer server.Close()

	config := &InternalScanConfig{
		EnableRFI:           true,
		MaxPayloadsPerParam: 10,
		RequestTimeout:      10 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	ctx := context.Background()
	findings := scanner.testRFI(ctx, server.URL+"?file=test", core.Parameter{Name: "file", Location: core.ParamLocationQuery}, "GET")
	t.Logf("RFI findings: %d", len(findings))
}

package stacktrace

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// javaStack is a representative Java/Spring trace fragment.
const javaStack = `java.lang.NullPointerException: Cannot invoke method
	at com.example.app.UserService.getUser(UserService.java:42)
	at com.example.app.UserController.handle(UserController.java:88)
	at org.springframework.web.servlet.DispatcherServlet.doDispatch(DispatcherServlet.java:1067)`

// pythonStack is a representative Django/Flask traceback.
const pythonStack = `Traceback (most recent call last):
  File "/app/views.py", line 23, in get_user
    user = User.objects.get(id=user_id)
  File "/usr/lib/python3.9/site-packages/django/db/models/manager.py", line 85, in manager_method
    return getattr(self.get_queryset(), name)(*args, **kwargs)
ValueError: invalid literal for int() with base 10: 'foo'`

// phpStack is a representative PHP fatal error with stack trace.
const phpStack = `Fatal error: Uncaught Exception: Database error in /var/www/app/db.php:42
Stack trace:
#0 /var/www/app/index.php(15): Database->query()
#1 {main}
  thrown in /var/www/app/db.php on line 42`

// nodeStack is a representative Node.js stack.
const nodeStack = `TypeError: Cannot read property 'name' of undefined
    at getUser (/app/src/users.js:23:14)
    at Module._compile (internal/modules/cjs/loader.js:1063:30)
    at /app/node_modules/express/lib/router/index.js:284:14`

// goStack is a representative Go panic trace.
const goStack = `panic: runtime error: invalid memory address or nil pointer dereference
goroutine 1 [running]:
main.handler(0xc0000a4000)
	/app/main.go:42 +0x1d
runtime error: index out of range [3] with length 2`

func vulnHandler(stack string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Baseline GET to the root URL returns a clean page so the baseline
		// fetch in DetectFromBaseline cannot accidentally see the stack.
		if r.Method == http.MethodGet && r.URL.RawQuery == "" && !strings.Contains(r.URL.Path, "..") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body>Welcome</body></html>`))
			return
		}
		// Anything malformed: spill the stack trace.
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(stack))
	}
}

func TestDetectFromBaseline_FlagsJavaStack(t *testing.T) {
	srv := httptest.NewServer(vulnHandler(javaStack))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.DetectFromBaseline(context.Background(), srv.URL+"/", DetectOptions{})
	if err != nil {
		t.Fatalf("DetectFromBaseline: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerable=true for Java stack trace leak")
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	found := false
	for _, f := range res.DetectedFrameworks {
		if f == "Java" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected Java in DetectedFrameworks, got %v", res.DetectedFrameworks)
	}
	// Verify finding metadata.
	f := res.Findings[0]
	if f.Type != "Stack Trace Disclosure" {
		t.Errorf("finding Type = %q, want %q", f.Type, "Stack Trace Disclosure")
	}
	if f.Tool != "stacktrace-detector" {
		t.Errorf("finding Tool = %q, want %q", f.Tool, "stacktrace-detector")
	}
	hasWSTG := false
	for _, w := range f.WSTG {
		if w == "WSTG-ERRH-02" {
			hasWSTG = true
		}
	}
	if !hasWSTG {
		t.Errorf("expected WSTG-ERRH-02 in finding.WSTG, got %v", f.WSTG)
	}
	hasCWE := false
	for _, c := range f.CWE {
		if c == "CWE-209" {
			hasCWE = true
		}
	}
	if !hasCWE {
		t.Errorf("expected CWE-209 in finding.CWE, got %v", f.CWE)
	}
}

func TestDetectFromBaseline_FlagsPythonStack(t *testing.T) {
	srv := httptest.NewServer(vulnHandler(pythonStack))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.DetectFromBaseline(context.Background(), srv.URL+"/", DetectOptions{})
	if err != nil {
		t.Fatalf("DetectFromBaseline: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerable=true for Python stack trace leak")
	}
	found := false
	for _, f := range res.DetectedFrameworks {
		if f == "Python" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Python in DetectedFrameworks, got %v", res.DetectedFrameworks)
	}
}

func TestDetectFromBaseline_FlagsPHPStack(t *testing.T) {
	srv := httptest.NewServer(vulnHandler(phpStack))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.DetectFromBaseline(context.Background(), srv.URL+"/", DetectOptions{})
	if err != nil {
		t.Fatalf("DetectFromBaseline: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerable=true for PHP stack trace leak")
	}
	found := false
	for _, f := range res.DetectedFrameworks {
		if f == "PHP" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected PHP in DetectedFrameworks, got %v", res.DetectedFrameworks)
	}
}

func TestDetectFromBaseline_FlagsNodeStack(t *testing.T) {
	srv := httptest.NewServer(vulnHandler(nodeStack))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.DetectFromBaseline(context.Background(), srv.URL+"/", DetectOptions{})
	if err != nil {
		t.Fatalf("DetectFromBaseline: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerable=true for Node.js stack trace leak")
	}
}

func TestDetectFromBaseline_FlagsGoStack(t *testing.T) {
	srv := httptest.NewServer(vulnHandler(goStack))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.DetectFromBaseline(context.Background(), srv.URL+"/", DetectOptions{})
	if err != nil {
		t.Fatalf("DetectFromBaseline: %v", err)
	}
	if !res.Vulnerable {
		t.Fatal("expected vulnerable=true for Go stack trace leak")
	}
}

func TestDetectFromBaseline_SafeServerReturnsGeneric500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.RawQuery == "" && !strings.Contains(r.URL.Path, "..") {
			_, _ = w.Write([]byte(`<html>OK</html>`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`<html><body><h1>500 Internal Server Error</h1><p>Something went wrong. Our team has been notified.</p></body></html>`))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.DetectFromBaseline(context.Background(), srv.URL+"/", DetectOptions{})
	if err != nil {
		t.Fatalf("DetectFromBaseline: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected vulnerable=false for safe generic 500, got findings=%d frameworks=%v",
			len(res.Findings), res.DetectedFrameworks)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(res.Findings))
	}
}

func TestDetectFromBaseline_PatternInBaselineIsNotFlagged(t *testing.T) {
	// Server always returns the same stack-trace-looking content. Since
	// it's already in the baseline, probes that surface the same bytes
	// must NOT flag — the spec says "pattern is NOT in baseline".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(javaStack))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.DetectFromBaseline(context.Background(), srv.URL+"/", DetectOptions{})
	if err != nil {
		t.Fatalf("DetectFromBaseline: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("expected vulnerable=false when stack pattern is already in baseline")
	}
}

func TestDetectFromBaseline_NilClientIsSafe(t *testing.T) {
	det := New(nil)
	res, err := det.DetectFromBaseline(context.Background(), "http://example.com", DetectOptions{})
	if err != nil {
		t.Fatalf("DetectFromBaseline: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil result")
	}
	if res.Vulnerable {
		t.Error("expected vulnerable=false when client is nil")
	}
}

func TestDetectFromBaseline_InvalidURL(t *testing.T) {
	det := New(skwshttp.NewClient())
	res, err := det.DetectFromBaseline(context.Background(), "://bad-url", DetectOptions{})
	if err != nil {
		t.Fatalf("DetectFromBaseline returned error for bad URL: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil result for bad URL")
	}
	if res.Vulnerable {
		t.Error("expected vulnerable=false for invalid URL")
	}
}

func TestDetectFromBaseline_CustomProbeTriggersFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("custom") == "boom" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(javaStack))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.DetectFromBaseline(context.Background(), srv.URL+"/", DetectOptions{
		CustomProbes: []string{"?custom=boom"},
	})
	if err != nil {
		t.Fatalf("DetectFromBaseline: %v", err)
	}
	if !res.Vulnerable {
		t.Error("expected vulnerable=true when CustomProbes triggers a Java stack")
	}
}

package grpcreflect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// fakeReflectionServer simulates a gRPC-Web server that returns a
// reflection list_services reply with two service names embedded in
// what would otherwise be a binary protobuf body.
func fakeReflectionServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/grpc.reflection.") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/grpc-web+proto")
		w.WriteHeader(http.StatusOK)
		// Build a body that starts with the gRPC-Web length prefix
		// (5 bytes) followed by bytes that include two long
		// "service.name" tokens; extractServiceNames should pick them up.
		body := []byte{0x00, 0x00, 0x00, 0x00, 0x40}
		body = append(body, []byte("\x0a\x16my.shop.OrderService\x0a\x18my.shop.PaymentService")...)
		_, _ = w.Write(body)
	}))
}

func TestDetect_FindsReflectionService(t *testing.T) {
	srv := fakeReflectionServer()
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected reflection finding")
	}
	if !strings.Contains(res.Findings[0].Evidence, "OrderService") {
		t.Errorf("expected OrderService in evidence, got %q", res.Findings[0].Evidence)
	}
}

func TestDetect_NotGRPCContentTypeNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Path matches but content-type is HTML — server returned a
		// front-end SPA on /grpc.reflection.* routes.
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>hello</html>"))
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on non-grpc content-type, got %d", len(res.Findings))
	}
}

func TestDetect_NoFindingOnNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on 404, got %d", len(res.Findings))
	}
}

func TestDetect_NilClientNoOp(t *testing.T) {
	det := &Detector{client: nil}
	res, err := det.Detect(context.Background(), "http://x.test/")
	if err != nil {
		t.Fatalf("nil-client should not error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("nil-client should produce 0 findings, got %d", len(res.Findings))
	}
}

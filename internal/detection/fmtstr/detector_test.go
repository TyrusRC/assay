package fmtstr

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ahttp "github.com/TyrusRC/assay/internal/http"
)

func TestDetect_Vulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.FormValue("input")
		if strings.Contains(v, "%x") {
			fmt.Fprint(w, "deadbeef cafebabe")
		} else {
			fmt.Fprint(w, "normal page content")
		}
	}))
	defer srv.Close()

	client := ahttp.NewClient()
	det := New(client)
	result, err := det.Detect(context.Background(), srv.URL, "input", "GET")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !result.Vulnerable {
		t.Error("expected vulnerable")
	}
	if len(result.Findings) == 0 {
		t.Error("expected at least one finding")
	}
}

func TestDetect_Safe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "normal page content")
	}))
	defer srv.Close()

	client := ahttp.NewClient()
	det := New(client)
	result, err := det.Detect(context.Background(), srv.URL, "input", "GET")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Vulnerable {
		t.Error("expected not vulnerable")
	}
}

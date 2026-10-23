package autocomplete

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	ahttp "github.com/TyrusRC/assay/internal/http"
)

func TestDetect_MissingAutocomplete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><form><input type="password" name="pass"></form></body></html>`)
	}))
	defer srv.Close()

	client := ahttp.NewClient()
	det := New(client)
	findings, err := det.Detect(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected finding for missing autocomplete")
	}
}

func TestDetect_AutocompleteOff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><form><input type="password" name="pass" autocomplete="off"></form></body></html>`)
	}))
	defer srv.Close()

	client := ahttp.NewClient()
	det := New(client)
	findings, err := det.Detect(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) != 0 {
		t.Error("expected no finding when autocomplete=off")
	}
}

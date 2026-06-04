package cmd

import (
	"reflect"
	"testing"
)

func TestResolveFormats(t *testing.T) {
	tests := []struct {
		name    string
		format  string
		json    bool
		html    bool
		want    []string
		wantErr bool
	}{
		{name: "default text", format: "", want: []string{"text"}},
		{name: "explicit list", format: "html,csv", want: []string{"html", "csv"}},
		{name: "dedup", format: "html,html,csv", want: []string{"html", "csv"}},
		{name: "json alias", format: "", json: true, want: []string{"json"}},
		{name: "html alias appends", format: "csv", html: true, want: []string{"csv", "html"}},
		{name: "unknown errors", format: "pdf", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveFormats(tt.format, tt.json, tt.html)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tt.format)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("resolveFormats(%q,%v,%v) = %v, want %v", tt.format, tt.json, tt.html, got, tt.want)
			}
		})
	}
}

func TestResolveFormats_MultiNeedsDir(t *testing.T) {
	if err := validateOutput([]string{"html", "csv"}, ""); err == nil {
		t.Error("expected error: multiple formats require --output-dir")
	}
	if err := validateOutput([]string{"html"}, ""); err != nil {
		t.Errorf("single format to stdout should be allowed: %v", err)
	}
}

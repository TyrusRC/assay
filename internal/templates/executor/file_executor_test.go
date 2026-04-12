package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/swiss-knife-for-web-security/skws/internal/templates"
)

func TestNewFileExecutor(t *testing.T) {
	exec := NewFileExecutor()
	if exec == nil {
		t.Fatal("NewFileExecutor() returned nil")
	}
	if exec.matcherEngine == nil {
		t.Error("matcherEngine not initialised")
	}
	if exec.maxFileSize != defaultMaxFileSize {
		t.Errorf("maxFileSize = %d, want %d", exec.maxFileSize, defaultMaxFileSize)
	}
}

func TestParseSize(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int64
		wantErr bool
	}{
		{"bytes no unit", "1024", 1024, false},
		{"bytes explicit B", "512B", 512, false},
		{"kilobytes KB", "10KB", 10 * 1024, false},
		{"kilobytes K", "8K", 8 * 1024, false},
		{"megabytes MB", "5MB", 5 * 1024 * 1024, false},
		{"megabytes M", "2M", 2 * 1024 * 1024, false},
		{"gigabytes GB", "1GB", 1024 * 1024 * 1024, false},
		{"gigabytes G", "1G", 1024 * 1024 * 1024, false},
		{"terabytes TB", "1TB", 1024 * 1024 * 1024 * 1024, false},
		{"lowercase mb", "3mb", 3 * 1024 * 1024, false},
		{"mixed case Mb", "4Mb", 4 * 1024 * 1024, false},
		{"zero bytes", "0", 0, false},
		{"empty string", "", 0, true},
		{"invalid unit", "10XB", 0, true},
		{"non-numeric", "abc", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSize(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSize(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseSize(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestFileExecutorMatchByContent(t *testing.T) {
	dir := t.TempDir()

	// Write a file that matches the word matcher.
	writeFile(t, filepath.Join(dir, "secret.txt"), "password: hunter2")
	// Write a file that does NOT match.
	writeFile(t, filepath.Join(dir, "clean.txt"), "nothing sensitive here")

	exec := NewFileExecutor()
	fileMatch := &templates.FileMatch{
		Extensions: []string{"txt"},
		Matchers: []templates.Matcher{
			{Type: "word", Words: []string{"password"}},
		},
	}

	results, err := exec.Execute(dir, fileMatch)
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Execute() returned %d results, want 1", len(results))
	}
	if !results[0].Matched {
		t.Error("result.Matched = false, want true")
	}
}

func TestFileExecutorExtensionFilter(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "file.go"), "sensitive_go_content")
	writeFile(t, filepath.Join(dir, "file.txt"), "sensitive_txt_content")

	exec := NewFileExecutor()
	fileMatch := &templates.FileMatch{
		Extensions: []string{"txt"},
		Matchers: []templates.Matcher{
			{Type: "word", Words: []string{"sensitive"}},
		},
	}

	results, err := exec.Execute(dir, fileMatch)
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	// Only the .txt file should be scanned.
	if len(results) != 1 {
		t.Fatalf("Execute() returned %d results, want 1", len(results))
	}
	if !strings.HasSuffix(results[0].URL, ".txt") {
		t.Errorf("matched file URL = %q, expected a .txt file", results[0].URL)
	}
}

func TestFileExecutorDenyList(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "config.log"), "password: secret")
	writeFile(t, filepath.Join(dir, "config.txt"), "password: secret")

	exec := NewFileExecutor()
	fileMatch := &templates.FileMatch{
		DenyList: []string{"log"},
		Matchers: []templates.Matcher{
			{Type: "word", Words: []string{"password"}},
		},
	}

	results, err := exec.Execute(dir, fileMatch)
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	// .log file should be denied; only .txt should match.
	if len(results) != 1 {
		t.Fatalf("Execute() returned %d results, want 1 (.txt only)", len(results))
	}
}

func TestFileExecutorMaxSize(t *testing.T) {
	dir := t.TempDir()

	// Write a large file that exceeds the override limit.
	bigContent := make([]byte, 100)
	for i := range bigContent {
		bigContent[i] = 'A'
	}
	writeFile(t, filepath.Join(dir, "big.txt"), string(bigContent))
	writeFile(t, filepath.Join(dir, "small.txt"), "AA")

	exec := NewFileExecutor()
	fileMatch := &templates.FileMatch{
		MaxSize: "50B",
		Matchers: []templates.Matcher{
			{Type: "word", Words: []string{"A"}},
		},
	}

	results, err := exec.Execute(dir, fileMatch)
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	// Only small.txt (2 bytes) should pass the size filter.
	if len(results) != 1 {
		t.Fatalf("Execute() returned %d results, want 1", len(results))
	}
}

func TestFileExecutorNoMatchersMatchesAll(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "a.txt"), "content a")
	writeFile(t, filepath.Join(dir, "b.txt"), "content b")

	exec := NewFileExecutor()
	// No matchers → MatchAll returns true for every file.
	fileMatch := &templates.FileMatch{}

	results, err := exec.Execute(dir, fileMatch)
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("Execute() returned %d results, want 2", len(results))
	}
}

func TestFileExecutorInvalidMaxSize(t *testing.T) {
	exec := NewFileExecutor()
	fileMatch := &templates.FileMatch{
		MaxSize: "notanumber",
	}
	_, err := exec.Execute(t.TempDir(), fileMatch)
	if err == nil {
		t.Error("Execute() should return error for invalid max-size")
	}
}

func TestFileExecutorNonExistentPath(t *testing.T) {
	exec := NewFileExecutor()
	fileMatch := &templates.FileMatch{}

	// Walk of a non-existent path should return an error.
	_, err := exec.Execute("/does/not/exist/at/all", fileMatch)
	if err == nil {
		t.Error("Execute() should return error for non-existent path")
	}
}

// writeFile is a test helper that creates a file with the given content.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("writeFile(%q): %v", path, err)
	}
}

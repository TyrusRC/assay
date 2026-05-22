package patparser

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestParseFile_MarkdownCodeBlocks extracts payloads from fenced code
// blocks in a PayloadAllTheThings-style markdown file.
func TestParseFile_MarkdownCodeBlocks(t *testing.T) {
	dir := t.TempDir()
	md := filepath.Join(dir, "MySQL Injection.md")
	body := strings.Join([]string{
		"# MySQL Injection",
		"",
		"## Basic UNION-based",
		"",
		"```sql",
		"' UNION SELECT 1,2,3 --",
		"' UNION SELECT user(),version(),database() --",
		"```",
		"",
		"## Time-based blind",
		"",
		"```",
		"1' AND SLEEP(5)--",
		"1' AND IF(1=1, SLEEP(5), 0)--",
		"```",
		"",
		"Inline `not-a-payload` text should not be picked up.",
	}, "\n")
	if err := os.WriteFile(md, []byte(body), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	payloads, err := ParseFile(md, "sqli")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(payloads) != 4 {
		t.Fatalf("expected 4 payloads, got %d: %+v", len(payloads), payloads)
	}

	values := make([]string, len(payloads))
	for i, p := range payloads {
		values[i] = p.Value
	}
	sort.Strings(values)
	want := []string{
		"' UNION SELECT 1,2,3 --",
		"' UNION SELECT user(),version(),database() --",
		"1' AND IF(1=1, SLEEP(5), 0)--",
		"1' AND SLEEP(5)--",
	}
	sort.Strings(want)
	for i, v := range want {
		if values[i] != v {
			t.Errorf("payload %d: want %q, got %q", i, v, values[i])
		}
	}

	for _, p := range payloads {
		if p.Class != "sqli" {
			t.Errorf("class: want sqli, got %q", p.Class)
		}
		if p.Subtype != "MySQL Injection" {
			t.Errorf("subtype: want %q, got %q", "MySQL Injection", p.Subtype)
		}
	}
}

// TestParseFile_MarkdownLanguageTag preserves the code-block language so
// downstream consumers can disambiguate "sql" payloads from "bash"
// example commands in the same file.
func TestParseFile_MarkdownLanguageTag(t *testing.T) {
	dir := t.TempDir()
	md := filepath.Join(dir, "XSS Filter Bypass.md")
	body := strings.Join([]string{
		"# XSS Filter Bypass",
		"",
		"```html",
		"<img src=x onerror=alert(1)>",
		"```",
		"",
		"```bash",
		"# Example exploitation command, not a payload",
		"curl http://target/?x=foo",
		"```",
	}, "\n")
	if err := os.WriteFile(md, []byte(body), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	payloads, err := ParseFile(md, "xss")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	// Bash blocks should be filtered out (shell commands aren't payloads).
	if len(payloads) != 1 {
		t.Fatalf("expected 1 payload (bash filtered), got %d: %+v", len(payloads), payloads)
	}
	if payloads[0].Lang != "html" {
		t.Errorf("lang: want html, got %q", payloads[0].Lang)
	}
}

// TestParseFile_IntruderTextFile reads a one-payload-per-line .txt file
// from the Intruder/ subfolders that PayloadAllTheThings uses for raw
// payload lists.
func TestParseFile_IntruderTextFile(t *testing.T) {
	dir := t.TempDir()
	txt := filepath.Join(dir, "xss-payload-list.txt")
	body := strings.Join([]string{
		"<script>alert(1)</script>",
		`<img src=x onerror=alert(2)>`,
		"# this is a comment, skip",
		"",
		"<svg/onload=alert(3)>",
	}, "\n")
	if err := os.WriteFile(txt, []byte(body), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	payloads, err := ParseFile(txt, "xss")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(payloads) != 3 {
		t.Fatalf("expected 3 payloads (comment + blank skipped), got %d: %+v", len(payloads), payloads)
	}
}

// TestParseFile_RejectOversizePayload guards against picking up entire
// code listings (full PoC scripts) as "payloads".
func TestParseFile_RejectOversizePayload(t *testing.T) {
	dir := t.TempDir()
	md := filepath.Join(dir, "SQLi.md")
	huge := strings.Repeat("A", 2048)
	body := strings.Join([]string{
		"```sql",
		huge,
		"```",
	}, "\n")
	if err := os.WriteFile(md, []byte(body), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	payloads, err := ParseFile(md, "sqli")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(payloads) != 0 {
		t.Errorf("expected 0 payloads (oversize filtered), got %d", len(payloads))
	}
}

// TestParseDir walks a fake PayloadAllTheThings tree and produces a
// catalog grouped by class.
func TestParseDir(t *testing.T) {
	root := t.TempDir()

	// Tree layout:
	//   root/
	//     SQL Injection/MySQL Injection.md
	//     SQL Injection/Intruder/payloads.txt
	//     XSS Injection/XSS Common.md
	//     README.md       (top-level, ignored — no class folder)
	mkdir := func(p string) {
		if err := os.MkdirAll(filepath.Join(root, p), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}
	}
	write := func(p, body string) {
		if err := os.WriteFile(filepath.Join(root, p), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	mkdir("SQL Injection/Intruder")
	mkdir("XSS Injection")
	write("README.md", "# top-level not a class folder")
	write("SQL Injection/MySQL Injection.md", "```sql\n' OR 1=1--\n```")
	write("SQL Injection/Intruder/payloads.txt", "' OR 'a'='a\n' UNION SELECT NULL--")
	write("XSS Injection/XSS Common.md", "```html\n<script>alert(1)</script>\n```")

	cat, err := ParseDir(root)
	if err != nil {
		t.Fatalf("ParseDir: %v", err)
	}
	if got := classCount(cat, "sqli"); got != 3 {
		t.Errorf("sqli count: want 3, got %d", got)
	}
	if got := classCount(cat, "xss"); got != 1 {
		t.Errorf("xss count: want 1, got %d", got)
	}
}

// TestParseDir_UnknownFolder still classifies an unknown top-level
// folder by slugifying its name (so the parser doesn't lose payloads
// when PayloadAllTheThings adds a new category).
func TestParseDir_UnknownFolder(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "Brand New Class"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "Brand New Class", "README.md"),
		[]byte("```\nfoo-payload\n```"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cat, err := ParseDir(root)
	if err != nil {
		t.Fatalf("ParseDir: %v", err)
	}
	if got := classCount(cat, "brand-new-class"); got != 1 {
		t.Errorf("brand-new-class count: want 1, got %d", got)
	}
}

// TestParseFile_NonexistentFile returns an error rather than silently
// emitting zero payloads — callers want to know about typo'd paths.
func TestParseFile_NonexistentFile(t *testing.T) {
	if _, err := ParseFile("/no/such/file.md", "sqli"); err == nil {
		t.Errorf("expected error for nonexistent file")
	}
}

func classCount(cat *Catalog, class string) int {
	n := 0
	for _, p := range cat.Payloads {
		if p.Class == class {
			n++
		}
	}
	return n
}

package htparser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TyrusRC/assay/internal/payloads/sync/patparser"
)

// TestClassForPath maps a HackTricks-style path slug to an attack
// class via the multi-keyword table.
func TestClassForPath(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"pentesting-web/xss-cross-site-scripting/README.md", "xss"},
		{"pentesting-web/sql-injection/mysql.md", "sqli"},
		{"pentesting-web/ssrf-server-side-request-forgery.md", "ssrf"},
		{"pentesting-web/ssti-server-side-template-injection.md", "ssti"},
		{"pentesting-web/command-injection.md", "cmdi"},
		{"pentesting-web/xxe-xee-xml-external-entity.md", "xxe"},
		{"pentesting-web/nosql-injection.md", "nosql"},
		{"pentesting-web/ldap-injection.md", "ldap"},
		{"pentesting-web/file-inclusion/README.md", "lfi"},
		{"pentesting-web/csrf-cross-site-request-forgery.md", "csrf"},
		{"pentesting-web/crlf-0d-0a.md", "crlf"},
		{"pentesting-web/jwt-vulnerabilities.md", "jwt"},
		{"pentesting-web/deserialization/README.md", "deser"},
		{"pentesting-web/open-redirect.md", "redirect"},
		{"pentesting-web/cors-bypass.md", "cors"},
		{"pentesting-web/graphql.md", "graphql"},
		{"some-unrelated-page.md", ""}, // unclassified → skip
	}
	for _, tc := range cases {
		got := ClassForPath(tc.path)
		if got != tc.want {
			t.Errorf("ClassForPath(%q): want %q, got %q", tc.path, tc.want, got)
		}
	}
}

// TestParseDir walks a fake HackTricks tree, classifies pages by their
// relative path, and extracts payloads from the markdown.
func TestParseDir(t *testing.T) {
	root := t.TempDir()
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

	mkdir("pentesting-web/xss-cross-site-scripting")
	mkdir("pentesting-web/sql-injection")
	mkdir("pentesting-web/random-essay") // no matching keywords

	write("pentesting-web/xss-cross-site-scripting/README.md", strings.Join([]string{
		"# XSS",
		"```html",
		"<svg/onload=alert(1)>",
		"<img src=x onerror=alert(2)>",
		"```",
	}, "\n"))
	write("pentesting-web/sql-injection/mysql.md", strings.Join([]string{
		"# MySQL",
		"```sql",
		"' OR 1=1--",
		"```",
	}, "\n"))
	write("pentesting-web/random-essay/page.md", strings.Join([]string{
		"# A philosophical essay",
		"```",
		"some-unclassified-snippet",
		"```",
	}, "\n"))

	cat, err := ParseDir(root)
	if err != nil {
		t.Fatalf("ParseDir: %v", err)
	}
	if got := classCount(cat, "xss"); got != 2 {
		t.Errorf("xss count: want 2, got %d", got)
	}
	if got := classCount(cat, "sqli"); got != 1 {
		t.Errorf("sqli count: want 1, got %d", got)
	}
	// The unclassified page shouldn't produce any payloads.
	for _, p := range cat.Payloads {
		if p.Class == "" {
			t.Errorf("expected no empty-class payloads; got %+v", p)
		}
	}
}

// TestParseDir_SkipsNodeModules guards against accidental ingestion of
// vendored dependencies that some HackTricks book builds drop in tree
// (node_modules, _book, etc.).
func TestParseDir_SkipsNoise(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"node_modules/xss", ".git/xss", "_book/xss"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(root, dir, "README.md"),
			[]byte("```html\n<should-not-be-ingested>\n```"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	cat, err := ParseDir(root)
	if err != nil {
		t.Fatalf("ParseDir: %v", err)
	}
	if len(cat.Payloads) != 0 {
		t.Errorf("expected 0 payloads (noise filtered); got %d: %+v", len(cat.Payloads), cat.Payloads)
	}
}

// TestParseDir_Nonexistent returns an error.
func TestParseDir_Nonexistent(t *testing.T) {
	if _, err := ParseDir("/no/such/dir"); err == nil {
		t.Errorf("expected error")
	}
}

func classCount(cat *patparser.Catalog, class string) int {
	n := 0
	for _, p := range cat.Payloads {
		if p.Class == class {
			n++
		}
	}
	return n
}

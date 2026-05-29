package exposure

import (
	"strings"
	"testing"
)

func TestBackupExtensions_NonEmpty(t *testing.T) {
	exts := BackupExtensions()
	if len(exts) < 12 {
		t.Errorf("expected at least 12 backup extensions, got %d", len(exts))
	}
	required := []string{".bak", ".old", ".orig", "~", ".save", ".swp"}
	got := make(map[string]bool, len(exts))
	for _, e := range exts {
		got[e] = true
	}
	for _, r := range required {
		if !got[r] {
			t.Errorf("missing required backup extension: %q", r)
		}
	}
}

func TestGenerateBackupVariants_NormalFile(t *testing.T) {
	got := GenerateBackupVariants("index.php")
	if len(got) < 8 {
		t.Errorf("expected at least 8 variants for index.php, got %d: %v", len(got), got)
	}
	// Spot-check a few must-have variants.
	wantSubset := []string{
		"index.php.bak",
		"index.php.old",
		"index.php.orig",
		"index.php~",
		"index.php.save",
		".index.php.swp",
	}
	seen := make(map[string]bool, len(got))
	for _, v := range got {
		seen[v] = true
	}
	for _, w := range wantSubset {
		if !seen[w] {
			t.Errorf("expected variant %q in result, got: %v", w, got)
		}
	}
}

func TestGenerateBackupVariants_PathWithDirs(t *testing.T) {
	got := GenerateBackupVariants("admin/config.php")
	// Variants must preserve the directory prefix.
	for _, v := range got {
		if !strings.HasPrefix(v, "admin/") {
			t.Errorf("variant %q dropped directory prefix", v)
		}
	}
	// .swp variant prefixes the basename with dot, not the whole path.
	wantSwp := "admin/.config.php.swp"
	seen := false
	for _, v := range got {
		if v == wantSwp {
			seen = true
		}
	}
	if !seen {
		t.Errorf("expected %q in variants, got: %v", wantSwp, got)
	}
}

func TestGenerateBackupVariants_EmptyInput(t *testing.T) {
	if got := GenerateBackupVariants(""); got != nil {
		t.Errorf("expected nil for empty input, got %v", got)
	}
}

func TestGenerateBackupVariants_DeduplicatesAndStripsInput(t *testing.T) {
	got := GenerateBackupVariants("index.php")
	seen := make(map[string]int, len(got))
	for _, v := range got {
		seen[v]++
		if v == "index.php" {
			t.Errorf("variant set should not contain the input path verbatim")
		}
	}
	for v, n := range seen {
		if n > 1 {
			t.Errorf("duplicate variant %q (count=%d)", v, n)
		}
	}
}

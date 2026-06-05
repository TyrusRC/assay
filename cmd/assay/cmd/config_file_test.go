package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "assay.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

func TestLoadFileConfig_Valid(t *testing.T) {
	path := writeTempConfig(t, `
targets:
  - https://a.example.com
  - https://b.example.com
profile: thorough
format: sarif,html
output_dir: ./reports
fail_on: high
concurrency: 8
timeout: 15m
crawl: true
crawl_depth: 2
nuclei_tags: cve,rce
`)
	fc, err := loadFileConfig(path)
	if err != nil {
		t.Fatalf("loadFileConfig: %v", err)
	}
	if len(fc.Targets) != 2 || fc.Targets[0] != "https://a.example.com" {
		t.Errorf("targets = %v", fc.Targets)
	}
	if fc.Profile != "thorough" || fc.Format != "sarif,html" || fc.FailOn != "high" {
		t.Errorf("unexpected scalar fields: %+v", fc)
	}
	if fc.Concurrency != 8 || fc.Timeout != "15m" || fc.CrawlDepth != 2 || !fc.Crawl {
		t.Errorf("unexpected numeric/bool fields: %+v", fc)
	}
}

func TestLoadFileConfig_UnknownFieldRejected(t *testing.T) {
	path := writeTempConfig(t, "bogus_key: 1\n")
	if _, err := loadFileConfig(path); err == nil {
		t.Error("expected error on unknown config key, got nil")
	}
}

func TestLoadFileConfig_Missing(t *testing.T) {
	if _, err := loadFileConfig(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestResolveConfigPath(t *testing.T) {
	// Explicit path wins regardless of existence checks.
	if p, ok := resolveConfigPath("/x/custom.yaml", func(string) bool { return false }); !ok || p != "/x/custom.yaml" {
		t.Errorf("explicit path: got (%q,%v)", p, ok)
	}
	// Auto-detect picks the first existing default.
	exists := func(name string) bool { return name == "assay.yml" }
	if p, ok := resolveConfigPath("", exists); !ok || p != "assay.yml" {
		t.Errorf("auto-detect: got (%q,%v)", p, ok)
	}
	// Nothing found.
	if _, ok := resolveConfigPath("", func(string) bool { return false }); ok {
		t.Error("expected not-found when no default exists")
	}
}

func TestPickHelpers(t *testing.T) {
	if got := pickString(false, "cur", "file"); got != "file" {
		t.Errorf("pickString unchanged = %q, want file", got)
	}
	if got := pickString(true, "cur", "file"); got != "cur" {
		t.Errorf("pickString changed = %q, want cur", got)
	}
	if got := pickString(false, "cur", ""); got != "cur" {
		t.Errorf("pickString empty file = %q, want cur", got)
	}
	if got := pickInt(false, 3, 8); got != 8 {
		t.Errorf("pickInt unchanged = %d, want 8", got)
	}
	if got := pickInt(false, 3, 0); got != 3 {
		t.Errorf("pickInt zero file = %d, want 3", got)
	}
	if got := pickBool(false, false, true); !got {
		t.Error("pickBool unchanged should take file value")
	}
	if got := pickBool(true, false, true); got {
		t.Error("pickBool changed should keep cur")
	}
}

func TestApplyFileConfig_FlagPrecedence(t *testing.T) {
	// Save and restore mutated globals.
	saveProfile, saveFormat, saveFailOn := profile, formatList, failOn
	saveConc, saveTimeout, saveCrawl := concurrency, timeout, crawl
	saveTargets := cfgFileTargets
	t.Cleanup(func() {
		profile, formatList, failOn = saveProfile, saveFormat, saveFailOn
		concurrency, timeout, crawl = saveConc, saveTimeout, saveCrawl
		cfgFileTargets = saveTargets
	})

	cmd := &cobra.Command{Use: "scan"}
	cmd.Flags().StringVar(&profile, "profile", "", "")
	cmd.Flags().StringVar(&formatList, "format", "", "")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "")
	cmd.Flags().IntVar(&concurrency, "concurrency", 3, "")
	cmd.Flags().DurationVar(&timeout, "timeout", time.Minute, "")
	cmd.Flags().BoolVar(&crawl, "crawl", false, "")

	// User explicitly set --format on the CLI; it must win over the file.
	if err := cmd.Flags().Set("format", "json"); err != nil {
		t.Fatalf("set format: %v", err)
	}

	fc := &fileConfig{
		Targets: []string{"https://x.example"},
		Profile: "thorough",
		Format:  "sarif",
		FailOn:  "high",
		Timeout: "10m",
		Crawl:   true,
	}
	if err := applyFileConfig(cmd, fc); err != nil {
		t.Fatalf("applyFileConfig: %v", err)
	}

	if formatList != "json" {
		t.Errorf("format = %q, want json (CLI must override file)", formatList)
	}
	if profile != "thorough" {
		t.Errorf("profile = %q, want thorough (from file)", profile)
	}
	if failOn != "high" {
		t.Errorf("failOn = %q, want high (from file)", failOn)
	}
	if timeout != 10*time.Minute {
		t.Errorf("timeout = %v, want 10m (from file)", timeout)
	}
	if !crawl {
		t.Error("crawl should be true from file")
	}
	if len(cfgFileTargets) != 1 || cfgFileTargets[0] != "https://x.example" {
		t.Errorf("cfgFileTargets = %v", cfgFileTargets)
	}
}

func TestApplyFileConfig_BadTimeout(t *testing.T) {
	saveTimeout := timeout
	t.Cleanup(func() { timeout = saveTimeout })
	cmd := &cobra.Command{Use: "scan"}
	cmd.Flags().DurationVar(&timeout, "timeout", time.Minute, "")
	if err := applyFileConfig(cmd, &fileConfig{Timeout: "not-a-duration"}); err == nil {
		t.Error("expected error for malformed timeout")
	}
}

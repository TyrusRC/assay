package cmd

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// fileConfig mirrors the most frequently reused scan options so they can be
// captured in a YAML file instead of repeated on the command line. CLI flags
// always take precedence over file values; file values take precedence over
// built-in defaults.
type fileConfig struct {
	Targets     []string `yaml:"targets"`
	Profile     string   `yaml:"profile"`
	Format      string   `yaml:"format"`
	OutputDir   string   `yaml:"output_dir"`
	FailOn      string   `yaml:"fail_on"`
	Concurrency int      `yaml:"concurrency"`
	Timeout     string   `yaml:"timeout"`
	Proxy       string   `yaml:"proxy"`
	Insecure    bool     `yaml:"insecure"`
	UserAgent   string   `yaml:"user_agent"`
	Cookie      string   `yaml:"cookie"`
	Headers     []string `yaml:"headers"`
	Crawl       bool     `yaml:"crawl"`
	CrawlDepth  int      `yaml:"crawl_depth"`
	CrawlPages  int      `yaml:"crawl_max_pages"`
	NucleiTags  string   `yaml:"nuclei_tags"`
	NucleiSev   string   `yaml:"nuclei_severity"`
}

// defaultConfigFiles are auto-detected in the working directory when --config
// is not given. The first that exists is loaded.
var defaultConfigFiles = []string{"assay.yaml", "assay.yml", ".assay.yaml"}

// loadFileConfig reads and parses a YAML config file. Unknown keys are
// rejected so typos surface as errors rather than being silently ignored.
func loadFileConfig(path string) (*fileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var fc fileConfig
	if err := dec.Decode(&fc); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return &fc, nil
}

// resolveConfigPath returns the config path to load: the explicit --config
// value when set, otherwise the first auto-detected default file that exists.
// The returned bool reports whether a path was found.
func resolveConfigPath(explicit string, exists func(string) bool) (string, bool) {
	if explicit != "" {
		return explicit, true
	}
	for _, name := range defaultConfigFiles {
		if exists(name) {
			return name, true
		}
	}
	return "", false
}

// applyConfigFile loads the config file (explicit or auto-detected) and copies
// its values into the command's flag variables for any flag the user did not
// set explicitly on the command line.
func applyConfigFile(cmd *cobra.Command) error {
	path, found := resolveConfigPath(configPath, fileExists)
	if !found {
		return nil
	}
	fc, err := loadFileConfig(path)
	if err != nil {
		return err
	}
	return applyFileConfig(cmd, fc)
}

// fileExists reports whether the named file exists and is not a directory.
func fileExists(name string) bool {
	info, err := os.Stat(name)
	return err == nil && !info.IsDir()
}

// flagChanged reports whether the named flag was set on the command line,
// checking both local and inherited (persistent) flag sets.
func flagChanged(cmd *cobra.Command, name string) bool {
	if f := cmd.Flags().Lookup(name); f != nil {
		return f.Changed
	}
	if f := cmd.InheritedFlags().Lookup(name); f != nil {
		return f.Changed
	}
	return false
}

// applyFileConfig writes file values onto the package-level flag variables,
// skipping any flag the user changed on the command line.
func applyFileConfig(cmd *cobra.Command, fc *fileConfig) error {
	changed := func(name string) bool { return flagChanged(cmd, name) }

	cfgFileTargets = fc.Targets

	profile = pickString(changed("profile"), profile, fc.Profile)
	formatList = pickString(changed("format"), formatList, fc.Format)
	outputDir = pickString(changed("output-dir"), outputDir, fc.OutputDir)
	failOn = pickString(changed("fail-on"), failOn, fc.FailOn)
	concurrency = pickInt(changed("concurrency"), concurrency, fc.Concurrency)
	proxy = pickString(changed("proxy"), proxy, fc.Proxy)
	insecure = pickBool(changed("insecure"), insecure, fc.Insecure)
	userAgent = pickString(changed("user-agent"), userAgent, fc.UserAgent)
	cookies = pickString(changed("cookie"), cookies, fc.Cookie)
	crawl = pickBool(changed("crawl"), crawl, fc.Crawl)
	crawlDepth = pickInt(changed("crawl-depth"), crawlDepth, fc.CrawlDepth)
	crawlPages = pickInt(changed("crawl-max-pages"), crawlPages, fc.CrawlPages)
	nucleiTags = pickString(changed("nuclei-tags"), nucleiTags, fc.NucleiTags)
	nucleiSev = pickString(changed("nuclei-severity"), nucleiSev, fc.NucleiSev)

	if !changed("header") && len(headers) == 0 {
		headers = fc.Headers
	}

	if fc.Timeout != "" && !changed("timeout") {
		d, err := time.ParseDuration(fc.Timeout)
		if err != nil {
			return fmt.Errorf("config timeout %q: %w", fc.Timeout, err)
		}
		timeout = d
	}
	return nil
}

func pickString(changed bool, cur, fileVal string) string {
	if !changed && fileVal != "" {
		return fileVal
	}
	return cur
}

func pickInt(changed bool, cur, fileVal int) int {
	if !changed && fileVal != 0 {
		return fileVal
	}
	return cur
}

func pickBool(changed, cur, fileVal bool) bool {
	if !changed {
		return fileVal
	}
	return cur
}

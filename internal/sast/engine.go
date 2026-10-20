package sast

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

type Config struct {
	Targets      []string
	Verbose      bool
	Concurrency  int
	ExcludeDirs  []string
	MaxFileSize  int64
	SecretsOnly  bool
	SCAOnly      bool
	ConfigOnly   bool
}

type Result struct {
	Findings     core.Findings
	FilesScanned int
	Duration     time.Duration
}

var defaultExcludeDirs = []string{
	".git", "node_modules", "vendor", "__pycache__", ".venv", "venv",
	".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
	".next", ".nuxt", ".output", "coverage",
}

func Scan(ctx context.Context, cfg *Config) (*Result, error) {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 8
	}
	if cfg.MaxFileSize <= 0 {
		cfg.MaxFileSize = 1 << 20 // 1MB
	}

	excludes := append(defaultExcludeDirs, cfg.ExcludeDirs...)

	start := time.Now()
	var allFindings core.Findings
	var mu sync.Mutex
	var filesScanned int

	if !cfg.SCAOnly && !cfg.ConfigOnly {
		files := collectFiles(cfg.Targets, excludes, cfg.MaxFileSize)
		filesScanned = len(files)
		if cfg.Verbose {
			fmt.Fprintf(os.Stderr, "[*] Secret scan: %d files to check\n", len(files))
		}
		findings := scanSecrets(ctx, files, cfg.Concurrency)
		mu.Lock()
		allFindings = append(allFindings, findings...)
		mu.Unlock()
	}

	if !cfg.SecretsOnly && !cfg.ConfigOnly {
		if cfg.Verbose {
			fmt.Fprintf(os.Stderr, "[*] SCA: scanning dependency manifests...\n")
		}
		findings := scanDependencies(ctx, cfg.Targets, excludes, cfg.Verbose)
		mu.Lock()
		allFindings = append(allFindings, findings...)
		mu.Unlock()
	}

	if !cfg.SecretsOnly && !cfg.SCAOnly {
		if cfg.Verbose {
			fmt.Fprintf(os.Stderr, "[*] Config: checking configuration files...\n")
		}
		findings := scanConfigFiles(cfg.Targets, excludes, cfg.Verbose)
		mu.Lock()
		allFindings = append(allFindings, findings...)
		mu.Unlock()
	}

	allFindings = allFindings.Deduplicate()
	allFindings.SortBySeverity()

	return &Result{
		Findings:     allFindings,
		FilesScanned: filesScanned,
		Duration:     time.Since(start),
	}, nil
}

func collectFiles(targets []string, excludeDirs []string, maxSize int64) []string {
	var files []string
	for _, target := range targets {
		filepath.WalkDir(target, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if isExcluded(d.Name(), excludeDirs) {
					return filepath.SkipDir
				}
				return nil
			}
			if isBinaryExtension(d.Name()) {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Size() > maxSize || info.Size() == 0 {
				return nil
			}
			files = append(files, path)
			return nil
		})
	}
	return files
}

func scanSecrets(ctx context.Context, files []string, concurrency int) core.Findings {
	var findings core.Findings
	var mu sync.Mutex

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, path := range files {
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()

			ff := scanFileForSecrets(p)
			if len(ff) > 0 {
				mu.Lock()
				findings = append(findings, ff...)
				mu.Unlock()
			}
		}(path)
	}
	wg.Wait()
	return findings
}

func scanFileForSecrets(path string) core.Findings {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	// Quick binary check on first 512 bytes
	header := make([]byte, 512)
	n, _ := f.Read(header)
	if isBinaryContent(header[:n]) {
		return nil
	}
	f.Seek(0, 0)

	var findings core.Findings
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 256*1024), 256*1024)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := sc.Text()
		for _, pat := range secretPatterns {
			match := pat.Regex.FindString(line)
			if match == "" {
				continue
			}
			finding := core.NewFinding("hardcoded-secret", pat.Severity)
			finding.Tool = "sast-secrets"
			finding.Title = pat.Name
			finding.Description = pat.Description
			finding.URL = path
			finding.Evidence = fmt.Sprintf("Line %d: %s", lineNum, redactMatch(strings.TrimSpace(line), match))
			finding.CWE = pat.CWE
			finding.Remediation = pat.Remediation
			finding.Confidence = pat.Confidence
			finding.Metadata["line"] = lineNum
			finding.Metadata["pattern"] = pat.Name
			findings = append(findings, finding)
		}
	}
	return findings
}

func isExcluded(name string, excludeDirs []string) bool {
	for _, e := range excludeDirs {
		if strings.EqualFold(name, e) {
			return true
		}
	}
	return false
}

func isBinaryContent(data []byte) bool {
	for _, b := range data {
		if b == 0 {
			return true
		}
	}
	return false
}

var binaryExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".bmp": true,
	".ico": true, ".webp": true, ".svg": true, ".mp4": true, ".mp3": true,
	".avi": true, ".mov": true, ".wmv": true, ".flv": true, ".woff": true,
	".woff2": true, ".ttf": true, ".eot": true, ".otf": true, ".pdf": true,
	".zip": true, ".tar": true, ".gz": true, ".bz2": true, ".xz": true,
	".rar": true, ".7z": true, ".exe": true, ".dll": true, ".so": true,
	".dylib": true, ".class": true, ".jar": true, ".war": true, ".pyc": true,
	".pyo": true, ".o": true, ".a": true, ".lib": true, ".bin": true,
	".dat": true, ".db": true, ".sqlite": true, ".sqlite3": true,
	".DS_Store": true, ".sum": true, ".lock": true,
}

func isBinaryExtension(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return binaryExts[ext]
}

package sast

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

const (
	osvBatchURL    = "https://api.osv.dev/v1/querybatch"
	osvBatchSize   = 100
	osvRateLimit   = 10
	scaMaxFileSize = 50 << 20 // 50MB
)

type dependency struct {
	Name      string
	Version   string
	Ecosystem string
	Manifest  string
}

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvVuln struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Aliases  []string `json:"aliases"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []osvVuln `json:"vulns"`
	} `json:"results"`
}

var scaClient = &http.Client{Timeout: 30 * time.Second}

func scanDependencies(ctx context.Context, targets []string, excludeDirs []string, verbose bool) core.Findings {
	var deps []dependency
	for _, target := range targets {
		filepath.WalkDir(target, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				if d != nil && d.IsDir() && isExcluded(d.Name(), excludeDirs) {
					return filepath.SkipDir
				}
				return nil
			}
			name := d.Name()
			switch name {
			case "package.json":
				deps = append(deps, parsePackageJSON(path)...)
			case "package-lock.json":
				deps = append(deps, parsePackageLock(path)...)
			case "go.mod":
				deps = append(deps, parseGoMod(path)...)
			case "requirements.txt":
				deps = append(deps, parsePythonRequirements(path)...)
			case "Pipfile.lock":
				deps = append(deps, parsePipfileLock(path)...)
			case "Gemfile.lock":
				deps = append(deps, parseGemfileLock(path)...)
			case "composer.lock":
				deps = append(deps, parseComposerLock(path)...)
			case "pom.xml":
				deps = append(deps, parsePomXML(path)...)
			}
			return nil
		})
	}

	if len(deps) == 0 {
		return nil
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "[*] SCA: found %d dependencies across manifests\n", len(deps))
	}

	return queryOSV(ctx, deps, verbose)
}

func queryOSV(ctx context.Context, deps []dependency, verbose bool) core.Findings {
	var findings core.Findings
	var mu sync.Mutex
	limiter := time.NewTicker(time.Second / osvRateLimit)
	defer limiter.Stop()

	for i := 0; i < len(deps); i += osvBatchSize {
		select {
		case <-ctx.Done():
			return findings
		case <-limiter.C:
		}

		end := i + osvBatchSize
		if end > len(deps) {
			end = len(deps)
		}
		batch := deps[i:end]

		req := osvBatchRequest{Queries: make([]osvQuery, len(batch))}
		for j, dep := range batch {
			req.Queries[j].Package.Name = dep.Name
			req.Queries[j].Package.Ecosystem = dep.Ecosystem
			req.Queries[j].Version = dep.Version
		}

		body, err := json.Marshal(req)
		if err != nil {
			continue
		}

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, osvBatchURL, bytes.NewReader(body))
		if err != nil {
			continue
		}
		httpReq.Header.Set("Content-Type", "application/json")

		resp, err := scaClient.Do(httpReq)
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "[!] SCA: OSV API error: %v\n", err)
			}
			continue
		}

		var osvResp osvBatchResponse
		decErr := json.NewDecoder(io.LimitReader(resp.Body, 10<<20)).Decode(&osvResp)
		resp.Body.Close()
		if decErr != nil {
			continue
		}

		mu.Lock()
		for j, result := range osvResp.Results {
			if j >= len(batch) {
				break
			}
			dep := batch[j]
			for _, vuln := range result.Vulns {
				f := vulnToFinding(dep, vuln)
				findings = append(findings, f)
			}
		}
		mu.Unlock()
	}
	return findings
}

func vulnToFinding(dep dependency, vuln osvVuln) *core.Finding {
	severity := core.SeverityMedium
	for _, s := range vuln.Severity {
		if s.Type == "CVSS_V3" {
			severity = cvssToSeverity(s.Score)
		}
	}

	cves := filterCVEs(vuln.Aliases)
	cwe := []string{"CWE-1035"}
	var refs []string
	for _, r := range vuln.References {
		if r.URL != "" {
			refs = append(refs, r.URL)
		}
	}

	f := core.NewFinding("vulnerable-dependency", severity)
	f.Tool = "sast-sca"
	f.Title = fmt.Sprintf("%s: %s@%s", vuln.ID, dep.Name, dep.Version)
	f.Description = vuln.Summary
	f.URL = dep.Manifest
	f.Parameter = dep.Name + "@" + dep.Version
	f.Evidence = fmt.Sprintf("Vulnerability %s affects %s %s@%s", vuln.ID, dep.Ecosystem, dep.Name, dep.Version)
	f.CWE = cwe
	if len(cves) > 0 {
		f.CWE = append(cves, cwe...)
	}
	f.References = refs
	f.Remediation = "Update " + dep.Name + " to a patched version."
	f.Confidence = core.ConfidenceConfirmed
	f.Metadata["ecosystem"] = dep.Ecosystem
	f.Metadata["vuln_id"] = vuln.ID
	return f
}

func cvssToSeverity(score string) core.Severity {
	// score is a CVSS vector string; parse the numeric score prefix if present
	// OSV sometimes provides just "CVSS:3.1/AV:N/..." — extract base score
	// from the aliases or default to medium. For simplicity, check prefix.
	if strings.Contains(score, "9.") || strings.HasPrefix(score, "10") {
		return core.SeverityCritical
	}
	if strings.Contains(score, "7.") || strings.Contains(score, "8.") {
		return core.SeverityHigh
	}
	if strings.Contains(score, "4.") || strings.Contains(score, "5.") || strings.Contains(score, "6.") {
		return core.SeverityMedium
	}
	return core.SeverityLow
}

func filterCVEs(aliases []string) []string {
	var cves []string
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			cves = append(cves, a)
		}
	}
	return cves
}

// --- Manifest parsers ---

func parsePackageJSON(path string) []dependency {
	data, err := readLimited(path, scaMaxFileSize)
	if err != nil {
		return nil
	}
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if json.Unmarshal(data, &pkg) != nil {
		return nil
	}
	var deps []dependency
	for name, ver := range pkg.Dependencies {
		deps = append(deps, dependency{Name: name, Version: cleanVersion(ver), Ecosystem: "npm", Manifest: path})
	}
	for name, ver := range pkg.DevDependencies {
		deps = append(deps, dependency{Name: name, Version: cleanVersion(ver), Ecosystem: "npm", Manifest: path})
	}
	return deps
}

func parsePackageLock(path string) []dependency {
	data, err := readLimited(path, scaMaxFileSize)
	if err != nil {
		return nil
	}
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if json.Unmarshal(data, &lock) != nil {
		return nil
	}
	var deps []dependency
	if len(lock.Packages) > 0 {
		for key, pkg := range lock.Packages {
			name := strings.TrimPrefix(key, "node_modules/")
			if name == "" || pkg.Version == "" {
				continue
			}
			deps = append(deps, dependency{Name: name, Version: pkg.Version, Ecosystem: "npm", Manifest: path})
		}
	} else {
		for name, pkg := range lock.Dependencies {
			if pkg.Version == "" {
				continue
			}
			deps = append(deps, dependency{Name: name, Version: pkg.Version, Ecosystem: "npm", Manifest: path})
		}
	}
	return deps
}

var goModRequire = regexp.MustCompile(`^\s*(\S+)\s+(v\S+)`)

func parseGoMod(path string) []dependency {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var deps []dependency
	inRequire := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "require (") || strings.HasPrefix(line, "require(") {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}
		if inRequire || strings.HasPrefix(line, "require ") {
			target := line
			if !inRequire {
				target = strings.TrimPrefix(line, "require ")
			}
			m := goModRequire.FindStringSubmatch(target)
			if m != nil {
				deps = append(deps, dependency{Name: m[1], Version: m[2], Ecosystem: "Go", Manifest: path})
			}
		}
	}
	return deps
}

var pyReqLine = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*(\S+)`)

func parsePythonRequirements(path string) []dependency {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var deps []dependency
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := pyReqLine.FindStringSubmatch(line)
		if m != nil {
			deps = append(deps, dependency{Name: m[1], Version: m[2], Ecosystem: "PyPI", Manifest: path})
		}
	}
	return deps
}

func parsePipfileLock(path string) []dependency {
	data, err := readLimited(path, scaMaxFileSize)
	if err != nil {
		return nil
	}
	var lock struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}
	if json.Unmarshal(data, &lock) != nil {
		return nil
	}
	var deps []dependency
	for name, pkg := range lock.Default {
		deps = append(deps, dependency{Name: name, Version: cleanVersion(pkg.Version), Ecosystem: "PyPI", Manifest: path})
	}
	for name, pkg := range lock.Develop {
		deps = append(deps, dependency{Name: name, Version: cleanVersion(pkg.Version), Ecosystem: "PyPI", Manifest: path})
	}
	return deps
}

var gemLockEntry = regexp.MustCompile(`^\s{4}(\S+)\s+\((\S+)\)`)

func parseGemfileLock(path string) []dependency {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var deps []dependency
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		m := gemLockEntry.FindStringSubmatch(sc.Text())
		if m != nil {
			deps = append(deps, dependency{Name: m[1], Version: m[2], Ecosystem: "RubyGems", Manifest: path})
		}
	}
	return deps
}

func parseComposerLock(path string) []dependency {
	data, err := readLimited(path, scaMaxFileSize)
	if err != nil {
		return nil
	}
	var lock struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
		PackagesDev []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages-dev"`
	}
	if json.Unmarshal(data, &lock) != nil {
		return nil
	}
	var deps []dependency
	for _, pkg := range lock.Packages {
		deps = append(deps, dependency{Name: pkg.Name, Version: cleanVersion(pkg.Version), Ecosystem: "Packagist", Manifest: path})
	}
	for _, pkg := range lock.PackagesDev {
		deps = append(deps, dependency{Name: pkg.Name, Version: cleanVersion(pkg.Version), Ecosystem: "Packagist", Manifest: path})
	}
	return deps
}

var pomDep = regexp.MustCompile(`<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>`)

func parsePomXML(path string) []dependency {
	data, err := readLimited(path, scaMaxFileSize)
	if err != nil {
		return nil
	}
	var deps []dependency
	for _, m := range pomDep.FindAllStringSubmatch(string(data), -1) {
		name := m[1] + ":" + m[2]
		deps = append(deps, dependency{Name: name, Version: m[3], Ecosystem: "Maven", Manifest: path})
	}
	return deps
}

func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "==")
	v = strings.TrimPrefix(v, "^")
	v = strings.TrimPrefix(v, "~")
	v = strings.TrimPrefix(v, ">=")
	return v
}

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}

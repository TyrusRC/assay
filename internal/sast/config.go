package sast

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
)

type configCheck struct {
	FilePattern string
	Checker     func(path string) core.Findings
}

var configChecks = []configCheck{
	{FilePattern: ".env", Checker: checkEnvFile},
	{FilePattern: ".env.*", Checker: checkEnvFile},
	{FilePattern: "docker-compose.yml", Checker: checkDockerCompose},
	{FilePattern: "docker-compose.yaml", Checker: checkDockerCompose},
	{FilePattern: "Dockerfile", Checker: checkDockerfile},
	{FilePattern: "nginx.conf", Checker: checkNginxConfig},
}

func scanConfigFiles(targets []string, excludeDirs []string, verbose bool) core.Findings {
	var findings core.Findings
	for _, target := range targets {
		filepath.WalkDir(target, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				if d != nil && d.IsDir() && isExcluded(d.Name(), excludeDirs) {
					return filepath.SkipDir
				}
				return nil
			}
			name := d.Name()
			for _, check := range configChecks {
				matched, _ := filepath.Match(check.FilePattern, name)
				if matched || name == check.FilePattern {
					findings = append(findings, check.Checker(path)...)
				}
			}
			return nil
		})
	}
	if verbose && len(findings) > 0 {
		fmt.Fprintf(os.Stderr, "[*] Config checks: %d findings\n", len(findings))
	}
	return findings
}

func checkEnvFile(path string) core.Findings {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings core.Findings
	sc := bufio.NewScanner(f)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToUpper(parts[0])
		val := strings.Trim(parts[1], `"'`)
		if val == "" || val == "changeme" || val == "your-key-here" || val == "xxx" {
			continue
		}
		for _, keyword := range []string{"SECRET", "KEY", "PASSWORD", "TOKEN", "PRIVATE", "CREDENTIAL"} {
			if strings.Contains(key, keyword) {
				finding := core.NewFinding("config-secret-in-env", core.SeverityHigh)
				finding.Tool = "sast-config"
				finding.Title = fmt.Sprintf("Secret in .env file: %s", parts[0])
				finding.URL = path
				finding.Evidence = fmt.Sprintf("Line %d: %s=%s", lineNum, parts[0], redactValue(val))
				finding.CWE = []string{"CWE-798", "CWE-260"}
				finding.Remediation = "Use a secrets manager or ensure .env is in .gitignore and never committed."
				finding.Confidence = core.ConfidenceMedium
				finding.Metadata["line"] = lineNum
				findings = append(findings, finding)
				break
			}
		}
	}
	return findings
}

var (
	privilegedRe  = regexp.MustCompile(`(?i)privileged:\s*true`)
	hostNetworkRe = regexp.MustCompile(`(?i)network_mode:\s*['"]?host`)
)

func checkDockerCompose(path string) core.Findings {
	data, err := readLimited(path, 1<<20)
	if err != nil {
		return nil
	}
	content := string(data)
	var findings core.Findings

	if privilegedRe.MatchString(content) {
		f := core.NewFinding("config-docker-privileged", core.SeverityHigh)
		f.Tool = "sast-config"
		f.Title = "Privileged container in docker-compose"
		f.URL = path
		f.Evidence = "privileged: true"
		f.CWE = []string{"CWE-250"}
		f.Remediation = "Remove privileged mode and use specific capabilities instead."
		f.Confidence = core.ConfidenceConfirmed
		findings = append(findings, f)
	}
	if hostNetworkRe.MatchString(content) {
		f := core.NewFinding("config-docker-host-network", core.SeverityMedium)
		f.Tool = "sast-config"
		f.Title = "Host network mode in docker-compose"
		f.URL = path
		f.Evidence = "network_mode: host"
		f.CWE = []string{"CWE-284"}
		f.Remediation = "Use a custom bridge network instead of host network mode."
		f.Confidence = core.ConfidenceConfirmed
		findings = append(findings, f)
	}
	return findings
}

func checkDockerfile(path string) core.Findings {
	data, err := readLimited(path, 1<<20)
	if err != nil {
		return nil
	}
	content := string(data)
	var findings core.Findings

	hasUser := false
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(trimmed), "USER ") {
			hasUser = true
		}
	}
	if !hasUser && strings.Contains(strings.ToUpper(content), "FROM ") {
		f := core.NewFinding("config-docker-root", core.SeverityMedium)
		f.Tool = "sast-config"
		f.Title = "Dockerfile runs as root (no USER directive)"
		f.URL = path
		f.Evidence = "No USER directive found in Dockerfile"
		f.CWE = []string{"CWE-250"}
		f.Remediation = "Add a USER directive to run the container as a non-root user."
		f.Confidence = core.ConfidenceHigh
		findings = append(findings, f)
	}
	return findings
}

var (
	serverTokensRe = regexp.MustCompile(`(?i)server_tokens\s+on`)
)

func checkNginxConfig(path string) core.Findings {
	data, err := readLimited(path, 1<<20)
	if err != nil {
		return nil
	}
	content := string(data)
	var findings core.Findings

	if serverTokensRe.MatchString(content) {
		f := core.NewFinding("config-nginx-server-tokens", core.SeverityLow)
		f.Tool = "sast-config"
		f.Title = "Nginx server_tokens enabled"
		f.URL = path
		f.Evidence = "server_tokens on"
		f.CWE = []string{"CWE-200"}
		f.Remediation = "Set server_tokens off to hide the Nginx version."
		f.Confidence = core.ConfidenceConfirmed
		findings = append(findings, f)
	}
	return findings
}

func redactValue(val string) string {
	if len(val) <= 6 {
		return "***"
	}
	return val[:3] + "..." + val[len(val)-3:]
}

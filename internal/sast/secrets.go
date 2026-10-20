package sast

import (
	"regexp"

	"github.com/TyrusRC/assay/internal/core"
)

type secretPattern struct {
	Name        string
	Regex       *regexp.Regexp
	Severity    core.Severity
	Confidence  core.Confidence
	CWE         []string
	Description string
	Remediation string
}

var secretPatterns = []secretPattern{
	{
		Name:        "AWS Access Key ID",
		Regex:       regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Severity:    core.SeverityCritical,
		Confidence:  core.ConfidenceHigh,
		CWE:         []string{"CWE-798"},
		Description: "AWS access key ID found in source code",
		Remediation: "Remove the key, rotate it immediately, and use environment variables or a secrets manager.",
	},
	{
		Name:        "AWS Secret Access Key",
		Regex:       regexp.MustCompile(`(?i)aws.{0,20}(?:secret|key).{0,20}['"][0-9a-zA-Z/+=]{40}['"]`),
		Severity:    core.SeverityCritical,
		Confidence:  core.ConfidenceHigh,
		CWE:         []string{"CWE-798"},
		Description: "AWS secret access key found in source code",
		Remediation: "Remove the key, rotate it immediately, and use environment variables or AWS IAM roles.",
	},
	{
		Name:        "GitHub Personal Access Token",
		Regex:       regexp.MustCompile(`gh[ps]_[0-9a-zA-Z]{36}`),
		Severity:    core.SeverityHigh,
		Confidence:  core.ConfidenceHigh,
		CWE:         []string{"CWE-798"},
		Description: "GitHub personal access token found in source code",
		Remediation: "Revoke the token at github.com/settings/tokens and use environment variables.",
	},
	{
		Name:        "GitHub OAuth Token",
		Regex:       regexp.MustCompile(`gho_[0-9a-zA-Z]{36}`),
		Severity:    core.SeverityHigh,
		Confidence:  core.ConfidenceHigh,
		CWE:         []string{"CWE-798"},
		Description: "GitHub OAuth access token found in source code",
		Remediation: "Revoke the token and use proper OAuth flows with secure token storage.",
	},
	{
		Name:        "GitLab Personal Access Token",
		Regex:       regexp.MustCompile(`glpat-[0-9a-zA-Z\-]{20,}`),
		Severity:    core.SeverityHigh,
		Confidence:  core.ConfidenceHigh,
		CWE:         []string{"CWE-798"},
		Description: "GitLab personal access token found in source code",
		Remediation: "Revoke the token in GitLab settings and use CI/CD variables.",
	},
	{
		Name:        "Private Key",
		Regex:       regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		Severity:    core.SeverityCritical,
		Confidence:  core.ConfidenceConfirmed,
		CWE:         []string{"CWE-321"},
		Description: "Private key found in source code",
		Remediation: "Remove the key from the repository, rotate it, and store it in a secrets manager or vault.",
	},
	{
		Name:        "Slack Token",
		Regex:       regexp.MustCompile(`xox[bpors]-[0-9a-zA-Z-]{10,}`),
		Severity:    core.SeverityHigh,
		Confidence:  core.ConfidenceHigh,
		CWE:         []string{"CWE-798"},
		Description: "Slack API token found in source code",
		Remediation: "Revoke the token in Slack app settings and use environment variables.",
	},
	{
		Name:        "Stripe Secret Key",
		Regex:       regexp.MustCompile(`sk_(?:live|test)_[0-9a-zA-Z]{24,}`),
		Severity:    core.SeverityCritical,
		Confidence:  core.ConfidenceHigh,
		CWE:         []string{"CWE-798"},
		Description: "Stripe secret key found in source code",
		Remediation: "Roll the key in the Stripe dashboard and use environment variables.",
	},
	{
		Name:        "Stripe Publishable Key",
		Regex:       regexp.MustCompile(`pk_(?:live|test)_[0-9a-zA-Z]{24,}`),
		Severity:    core.SeverityLow,
		Confidence:  core.ConfidenceHigh,
		CWE:         []string{"CWE-798"},
		Description: "Stripe publishable key found in source code (low risk, but should be in config)",
		Remediation: "Move to an environment variable or config file excluded from version control.",
	},
	{
		Name:        "Google API Key",
		Regex:       regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		Severity:    core.SeverityHigh,
		Confidence:  core.ConfidenceMedium,
		CWE:         []string{"CWE-798"},
		Description: "Google API key found in source code",
		Remediation: "Restrict the key in Google Cloud Console and move to environment variables.",
	},
	{
		Name:        "Heroku API Key",
		Regex:       regexp.MustCompile(`(?i)heroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
		Severity:    core.SeverityHigh,
		Confidence:  core.ConfidenceMedium,
		CWE:         []string{"CWE-798"},
		Description: "Heroku API key found in source code",
		Remediation: "Regenerate the key and use Heroku config vars.",
	},
	{
		Name:        "JSON Web Token",
		Regex:       regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
		Severity:    core.SeverityMedium,
		Confidence:  core.ConfidenceMedium,
		CWE:         []string{"CWE-798"},
		Description: "Hardcoded JWT found in source code",
		Remediation: "Remove the token. If it's a test fixture, mark the file as excluded from secret scanning.",
	},
	{
		Name:        "Generic API Key Assignment",
		Regex:       regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*['"][0-9a-zA-Z]{20,}['"]`),
		Severity:    core.SeverityMedium,
		Confidence:  core.ConfidenceMedium,
		CWE:         []string{"CWE-798"},
		Description: "Generic API key or secret assignment found in source code",
		Remediation: "Move the value to an environment variable or secrets manager.",
	},
	{
		Name:        "Generic Password Assignment",
		Regex:       regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]`),
		Severity:    core.SeverityMedium,
		Confidence:  core.ConfidenceLow,
		CWE:         []string{"CWE-798", "CWE-259"},
		Description: "Hardcoded password found in source code",
		Remediation: "Remove the password and use environment variables or a secrets manager.",
	},
	{
		Name:        "Database Connection String",
		Regex:       regexp.MustCompile(`(?i)(?:mongodb|postgres|mysql|redis|amqp)://[^\s'"]+`),
		Severity:    core.SeverityHigh,
		Confidence:  core.ConfidenceMedium,
		CWE:         []string{"CWE-798", "CWE-200"},
		Description: "Database connection string with potential credentials found in source code",
		Remediation: "Move the connection string to an environment variable. Never embed credentials in URIs committed to source control.",
	},
}

func redactMatch(line, match string) string {
	if len(match) <= 8 {
		return line
	}
	visible := match[:4]
	tail := match[len(match)-4:]
	redacted := visible + "..." + tail
	return replaceFirst(line, match, redacted)
}

func replaceFirst(s, old, replacement string) string {
	i := indexOf(s, old)
	if i < 0 {
		return s
	}
	return s[:i] + replacement + s[i+len(old):]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

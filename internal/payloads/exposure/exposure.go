// Package exposure provides payloads for sensitive file exposure detection.
package exposure

// Category represents the category of sensitive file.
type Category string

const (
	CategoryConfig      Category = "config"
	CategoryVersionCtrl Category = "version_control"
	CategoryBackup      Category = "backup"
	CategoryDebug       Category = "debug"
	CategorySecret      Category = "secret"
	CategoryLog         Category = "log"
	CategoryIDE         Category = "ide"
	CategoryDatabase    Category = "database"
)

// Severity indicates the exposure severity.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Payload represents a sensitive file exposure payload.
type Payload struct {
	Path        string
	Category    Category
	Severity    Severity
	Description string
	Patterns    []string // Patterns to detect in response
}

var payloads = []Payload{
	// Environment files (Critical)
	{Path: ".env", Category: CategoryConfig, Severity: SeverityCritical, Description: "Environment file with secrets", Patterns: []string{"DB_PASSWORD", "API_KEY", "SECRET_KEY", "APP_KEY", "DATABASE_URL"}},
	{Path: ".env.local", Category: CategoryConfig, Severity: SeverityCritical, Description: "Local environment file", Patterns: []string{"DB_PASSWORD", "API_KEY", "SECRET_KEY"}},
	{Path: ".env.production", Category: CategoryConfig, Severity: SeverityCritical, Description: "Production environment file", Patterns: []string{"DB_PASSWORD", "API_KEY", "SECRET_KEY"}},
	{Path: ".env.backup", Category: CategoryConfig, Severity: SeverityCritical, Description: "Backup environment file", Patterns: []string{"DB_PASSWORD", "API_KEY", "SECRET_KEY"}},

	// Git files (High)
	{Path: ".git/config", Category: CategoryVersionCtrl, Severity: SeverityHigh, Description: "Git configuration with repository URLs", Patterns: []string{"[core]", "[remote", "url =", "repositoryformatversion"}},
	{Path: ".git/HEAD", Category: CategoryVersionCtrl, Severity: SeverityHigh, Description: "Git HEAD reference", Patterns: []string{"ref: refs/heads/"}},
	{Path: ".git/index", Category: CategoryVersionCtrl, Severity: SeverityHigh, Description: "Git index file", Patterns: []string{"DIRC"}},
	{Path: ".gitignore", Category: CategoryVersionCtrl, Severity: SeverityMedium, Description: "Git ignore file revealing structure", Patterns: []string{"node_modules", ".env", "vendor", "*.log"}},

	// Other VCS (High)
	{Path: ".svn/entries", Category: CategoryVersionCtrl, Severity: SeverityHigh, Description: "SVN entries file", Patterns: []string{"svn:wc:entries", "dir"}},
	{Path: ".svn/wc.db", Category: CategoryVersionCtrl, Severity: SeverityHigh, Description: "SVN database", Patterns: []string{"SQLite"}},
	{Path: ".hg/hgrc", Category: CategoryVersionCtrl, Severity: SeverityHigh, Description: "Mercurial configuration", Patterns: []string{"[paths]", "default ="}},

	// Config files (Critical/High)
	{Path: "config.php", Category: CategoryConfig, Severity: SeverityCritical, Description: "PHP configuration with credentials", Patterns: []string{"<?php", "password", "db_", "mysql"}},
	{Path: "config.json", Category: CategoryConfig, Severity: SeverityHigh, Description: "JSON configuration file", Patterns: []string{`"database"`, `"password"`, `"api_key"`}},
	{Path: "config.yaml", Category: CategoryConfig, Severity: SeverityHigh, Description: "YAML configuration file", Patterns: []string{"database:", "password:", "secret:"}},
	{Path: "config.yml", Category: CategoryConfig, Severity: SeverityHigh, Description: "YAML configuration file", Patterns: []string{"database:", "password:", "secret:"}},
	{Path: "wp-config.php", Category: CategoryConfig, Severity: SeverityCritical, Description: "WordPress configuration", Patterns: []string{"DB_NAME", "DB_USER", "DB_PASSWORD", "AUTH_KEY"}},
	{Path: "configuration.php", Category: CategoryConfig, Severity: SeverityCritical, Description: "Joomla configuration", Patterns: []string{"$host", "$user", "$password", "JConfig"}},
	{Path: "settings.php", Category: CategoryConfig, Severity: SeverityCritical, Description: "Drupal settings", Patterns: []string{"$databases", "hash_salt", "drupal"}},
	{Path: "database.yml", Category: CategoryConfig, Severity: SeverityCritical, Description: "Rails database config", Patterns: []string{"adapter:", "database:", "username:", "password:"}},

	// Web server configs (High)
	{Path: "web.config", Category: CategoryConfig, Severity: SeverityHigh, Description: "IIS configuration", Patterns: []string{"<configuration>", "connectionStrings", "appSettings"}},
	{Path: ".htaccess", Category: CategoryConfig, Severity: SeverityMedium, Description: "Apache configuration", Patterns: []string{"RewriteEngine", "RewriteRule", "AuthType"}},
	{Path: ".htpasswd", Category: CategorySecret, Severity: SeverityCritical, Description: "Apache password file", Patterns: []string{":", "$apr1$", "$2y$"}},
	{Path: "nginx.conf", Category: CategoryConfig, Severity: SeverityHigh, Description: "Nginx configuration", Patterns: []string{"server {", "location", "proxy_pass"}},

	// Backup files (High)
	{Path: "backup.sql", Category: CategoryBackup, Severity: SeverityCritical, Description: "SQL backup file", Patterns: []string{"CREATE TABLE", "INSERT INTO", "DROP TABLE"}},
	{Path: "backup.zip", Category: CategoryBackup, Severity: SeverityHigh, Description: "Backup archive", Patterns: []string{"PK"}},
	{Path: "backup.tar.gz", Category: CategoryBackup, Severity: SeverityHigh, Description: "Backup archive", Patterns: []string{"\x1f\x8b"}},
	{Path: "database.sql", Category: CategoryBackup, Severity: SeverityCritical, Description: "Database dump", Patterns: []string{"CREATE TABLE", "INSERT INTO"}},
	{Path: "dump.sql", Category: CategoryBackup, Severity: SeverityCritical, Description: "Database dump", Patterns: []string{"CREATE TABLE", "INSERT INTO"}},
	{Path: "db.sql", Category: CategoryBackup, Severity: SeverityCritical, Description: "Database dump", Patterns: []string{"CREATE TABLE", "INSERT INTO"}},

	// Debug files (High/Medium)
	{Path: "phpinfo.php", Category: CategoryDebug, Severity: SeverityHigh, Description: "PHP info page", Patterns: []string{"phpinfo()", "PHP Version", "Configuration"}},
	{Path: "info.php", Category: CategoryDebug, Severity: SeverityHigh, Description: "PHP info page", Patterns: []string{"phpinfo()", "PHP Version"}},
	{Path: "test.php", Category: CategoryDebug, Severity: SeverityMedium, Description: "Test file", Patterns: []string{"<?php", "test"}},
	{Path: "debug.php", Category: CategoryDebug, Severity: SeverityMedium, Description: "Debug file", Patterns: []string{"<?php", "debug"}},
	{Path: ".debug", Category: CategoryDebug, Severity: SeverityMedium, Description: "Debug flag file", Patterns: []string{}},

	// Secret files (Critical)
	{Path: "id_rsa", Category: CategorySecret, Severity: SeverityCritical, Description: "RSA private key", Patterns: []string{"-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----"}},
	{Path: "id_dsa", Category: CategorySecret, Severity: SeverityCritical, Description: "DSA private key", Patterns: []string{"-----BEGIN DSA PRIVATE KEY-----"}},
	{Path: "id_ecdsa", Category: CategorySecret, Severity: SeverityCritical, Description: "ECDSA private key", Patterns: []string{"-----BEGIN EC PRIVATE KEY-----"}},
	{Path: "id_ed25519", Category: CategorySecret, Severity: SeverityCritical, Description: "ED25519 private key", Patterns: []string{"-----BEGIN OPENSSH PRIVATE KEY-----"}},
	{Path: ".ssh/id_rsa", Category: CategorySecret, Severity: SeverityCritical, Description: "SSH private key", Patterns: []string{"-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----"}},
	{Path: "server.key", Category: CategorySecret, Severity: SeverityCritical, Description: "Server private key", Patterns: []string{"-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----"}},
	{Path: "private.key", Category: CategorySecret, Severity: SeverityCritical, Description: "Private key file", Patterns: []string{"-----BEGIN PRIVATE KEY-----"}},
	{Path: "credentials.json", Category: CategorySecret, Severity: SeverityCritical, Description: "Credentials file", Patterns: []string{`"client_secret"`, `"private_key"`, `"access_token"`}},
	{Path: "secrets.json", Category: CategorySecret, Severity: SeverityCritical, Description: "Secrets file", Patterns: []string{`"secret"`, `"api_key"`, `"token"`}},
	{Path: "secrets.yaml", Category: CategorySecret, Severity: SeverityCritical, Description: "Secrets file", Patterns: []string{"secret:", "api_key:", "token:"}},
	{Path: ".npmrc", Category: CategorySecret, Severity: SeverityHigh, Description: "NPM config with tokens", Patterns: []string{"//registry.npmjs.org/:_authToken", "_auth"}},
	{Path: ".dockercfg", Category: CategorySecret, Severity: SeverityHigh, Description: "Docker config", Patterns: []string{"auth", "email"}},

	// Log files (Medium)
	{Path: "error.log", Category: CategoryLog, Severity: SeverityMedium, Description: "Error log file", Patterns: []string{"error", "warning", "fatal", "exception"}},
	{Path: "access.log", Category: CategoryLog, Severity: SeverityMedium, Description: "Access log file", Patterns: []string{"GET", "POST", "HTTP/1"}},
	{Path: "debug.log", Category: CategoryLog, Severity: SeverityMedium, Description: "Debug log file", Patterns: []string{"debug", "trace", "info"}},
	{Path: "app.log", Category: CategoryLog, Severity: SeverityMedium, Description: "Application log", Patterns: []string{"error", "info", "warn"}},
	{Path: "logs/error.log", Category: CategoryLog, Severity: SeverityMedium, Description: "Error log file", Patterns: []string{"error", "warning"}},
	{Path: "logs/access.log", Category: CategoryLog, Severity: SeverityMedium, Description: "Access log file", Patterns: []string{"GET", "POST"}},

	// IDE files (Low/Medium)
	{Path: ".idea/workspace.xml", Category: CategoryIDE, Severity: SeverityLow, Description: "IntelliJ workspace", Patterns: []string{"<?xml", "project"}},
	{Path: ".vscode/settings.json", Category: CategoryIDE, Severity: SeverityLow, Description: "VS Code settings", Patterns: []string{"{", "settings"}},
	{Path: ".project", Category: CategoryIDE, Severity: SeverityLow, Description: "Eclipse project", Patterns: []string{"<?xml", "projectDescription"}},

	// Package files (Medium)
	{Path: "package.json", Category: CategoryConfig, Severity: SeverityLow, Description: "NPM package file", Patterns: []string{`"name"`, `"version"`, `"dependencies"`}},
	{Path: "composer.json", Category: CategoryConfig, Severity: SeverityLow, Description: "Composer package file", Patterns: []string{`"name"`, `"require"`, `"autoload"`}},
	{Path: "composer.lock", Category: CategoryConfig, Severity: SeverityLow, Description: "Composer lock file", Patterns: []string{`"packages"`, `"hash"`}},
	{Path: "package-lock.json", Category: CategoryConfig, Severity: SeverityLow, Description: "NPM lock file", Patterns: []string{`"lockfileVersion"`, `"dependencies"`}},
	{Path: "yarn.lock", Category: CategoryConfig, Severity: SeverityLow, Description: "Yarn lock file", Patterns: []string{"version", "resolved", "integrity"}},
	{Path: "Gemfile", Category: CategoryConfig, Severity: SeverityLow, Description: "Ruby gems file", Patterns: []string{"source", "gem "}},
	{Path: "Gemfile.lock", Category: CategoryConfig, Severity: SeverityLow, Description: "Ruby gems lock", Patterns: []string{"GEM", "specs:"}},
	{Path: "requirements.txt", Category: CategoryConfig, Severity: SeverityLow, Description: "Python requirements", Patterns: []string{"==", ">="}},
	{Path: "Pipfile", Category: CategoryConfig, Severity: SeverityLow, Description: "Python Pipfile", Patterns: []string{"[packages]", "[dev-packages]"}},
	{Path: "go.mod", Category: CategoryConfig, Severity: SeverityLow, Description: "Go module file", Patterns: []string{"module", "require"}},
	{Path: "go.sum", Category: CategoryConfig, Severity: SeverityLow, Description: "Go checksum file", Patterns: []string{"h1:"}},

	// Database files (Critical)
	{Path: "database.db", Category: CategoryDatabase, Severity: SeverityCritical, Description: "SQLite database", Patterns: []string{"SQLite format"}},
	{Path: "data.db", Category: CategoryDatabase, Severity: SeverityCritical, Description: "SQLite database", Patterns: []string{"SQLite format"}},
	{Path: "users.db", Category: CategoryDatabase, Severity: SeverityCritical, Description: "User database", Patterns: []string{"SQLite format"}},
	{Path: "app.db", Category: CategoryDatabase, Severity: SeverityCritical, Description: "Application database", Patterns: []string{"SQLite format"}},

	// AWS/Cloud files (Critical)
	{Path: ".aws/credentials", Category: CategorySecret, Severity: SeverityCritical, Description: "AWS credentials", Patterns: []string{"aws_access_key_id", "aws_secret_access_key"}},
	{Path: ".aws/config", Category: CategoryConfig, Severity: SeverityHigh, Description: "AWS config", Patterns: []string{"[profile", "region"}},
	{Path: ".boto", Category: CategorySecret, Severity: SeverityCritical, Description: "Boto credentials", Patterns: []string{"aws_access_key_id", "aws_secret_access_key"}},
	{Path: ".gcloud/credentials.json", Category: CategorySecret, Severity: SeverityCritical, Description: "GCP credentials", Patterns: []string{`"client_secret"`, `"refresh_token"`}},
	{Path: ".azure/credentials", Category: CategorySecret, Severity: SeverityCritical, Description: "Azure credentials", Patterns: []string{"client_id", "client_secret"}},

	// Additional common paths
	{Path: "crossdomain.xml", Category: CategoryConfig, Severity: SeverityMedium, Description: "Flash cross-domain policy", Patterns: []string{"cross-domain-policy", "allow-access-from"}},
	{Path: "clientaccesspolicy.xml", Category: CategoryConfig, Severity: SeverityMedium, Description: "Silverlight access policy", Patterns: []string{"access-policy", "cross-domain-access"}},
	{Path: "robots.txt", Category: CategoryConfig, Severity: SeverityLow, Description: "Robots file revealing paths", Patterns: []string{"Disallow:", "Allow:"}},
	{Path: "sitemap.xml", Category: CategoryConfig, Severity: SeverityLow, Description: "Sitemap file", Patterns: []string{"urlset", "url", "loc"}},
	{Path: ".DS_Store", Category: CategoryIDE, Severity: SeverityMedium, Description: "macOS metadata file", Patterns: []string{"Bud1"}},
	{Path: "Thumbs.db", Category: CategoryIDE, Severity: SeverityLow, Description: "Windows thumbnail cache", Patterns: []string{}},
}

// GetPayloads returns all sensitive file exposure payloads.
func GetPayloads() []Payload {
	return payloads
}

// GetByCategory returns payloads for a specific category.
func GetByCategory(category Category) []Payload {
	var result []Payload
	for _, p := range payloads {
		if p.Category == category {
			result = append(result, p)
		}
	}
	return result
}

// GetBySeverity returns payloads for a specific severity.
func GetBySeverity(severity Severity) []Payload {
	var result []Payload
	for _, p := range payloads {
		if p.Severity == severity {
			result = append(result, p)
		}
	}
	return result
}

// GetCriticalPayloads returns only critical severity payloads.
func GetCriticalPayloads() []Payload {
	return GetBySeverity(SeverityCritical)
}

// GetConfigPayloads returns configuration file payloads.
func GetConfigPayloads() []Payload {
	return GetByCategory(CategoryConfig)
}

// GetSecretPayloads returns secret file payloads.
func GetSecretPayloads() []Payload {
	return GetByCategory(CategorySecret)
}

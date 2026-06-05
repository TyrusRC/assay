package integrations

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// defaultHTTPTimeout bounds each issue-tracker API call.
const defaultHTTPTimeout = 30 * time.Second

// GitHubExporter files findings as issues in a GitHub repository via the REST
// API. BaseURL defaults to the public API and can be overridden for GitHub
// Enterprise or tests.
type GitHubExporter struct {
	// Repo is "owner/name".
	Repo string
	// Token is a GitHub token with repo/issues scope.
	Token string
	// BaseURL overrides the API root (default https://api.github.com).
	BaseURL string
	// HTTP is the client to use; a default is created when nil.
	HTTP *http.Client
}

// Name identifies the exporter.
func (g *GitHubExporter) Name() string { return "github" }

// Validate checks that the required configuration is present.
func (g *GitHubExporter) Validate() error {
	if strings.TrimSpace(g.Repo) == "" || !strings.Contains(g.Repo, "/") {
		return fmt.Errorf("github: --github-repo must be owner/name")
	}
	if strings.TrimSpace(g.Token) == "" {
		return fmt.Errorf("github: a token is required (set GITHUB_TOKEN)")
	}
	return nil
}

func (g *GitHubExporter) base() string {
	if g.BaseURL != "" {
		return strings.TrimRight(g.BaseURL, "/")
	}
	return "https://api.github.com"
}

// Export creates one GitHub issue per Issue and returns the number created.
func (g *GitHubExporter) Export(ctx context.Context, issues []Issue) (int, error) {
	url := g.base() + "/repos/" + g.Repo + "/issues"
	created := 0
	for _, iss := range issues {
		payload := map[string]any{
			"title":  iss.Title,
			"body":   iss.Body,
			"labels": iss.Labels,
		}
		if err := postJSON(ctx, g.HTTP, url, payload, func(req *http.Request) {
			req.Header.Set("Authorization", "Bearer "+g.Token)
			req.Header.Set("Accept", "application/vnd.github+json")
		}); err != nil {
			return created, err
		}
		created++
	}
	return created, nil
}

// JiraExporter files findings as issues in a Jira project via the REST API.
// Jira Cloud authenticates with basic auth using an account email and API token.
type JiraExporter struct {
	// BaseURL is the Jira site root, e.g. https://org.atlassian.net.
	BaseURL string
	// Project is the project key, e.g. "SEC".
	Project string
	// Email is the account email for basic auth.
	Email string
	// Token is the API token.
	Token string
	// IssueType is the issue type name (default "Bug").
	IssueType string
	// HTTP is the client to use; a default is created when nil.
	HTTP *http.Client
}

// Name identifies the exporter.
func (j *JiraExporter) Name() string { return "jira" }

// Validate checks that the required configuration is present.
func (j *JiraExporter) Validate() error {
	if strings.TrimSpace(j.BaseURL) == "" {
		return fmt.Errorf("jira: --jira-url is required")
	}
	if strings.TrimSpace(j.Project) == "" {
		return fmt.Errorf("jira: --jira-project is required")
	}
	if strings.TrimSpace(j.Email) == "" || strings.TrimSpace(j.Token) == "" {
		return fmt.Errorf("jira: email and token are required (set JIRA_EMAIL and JIRA_TOKEN)")
	}
	return nil
}

func (j *JiraExporter) issueType() string {
	if j.IssueType != "" {
		return j.IssueType
	}
	return "Bug"
}

// Export creates one Jira issue per Issue and returns the number created.
func (j *JiraExporter) Export(ctx context.Context, issues []Issue) (int, error) {
	url := strings.TrimRight(j.BaseURL, "/") + "/rest/api/2/issue"
	auth := base64.StdEncoding.EncodeToString([]byte(j.Email + ":" + j.Token))
	created := 0
	for _, iss := range issues {
		payload := map[string]any{
			"fields": map[string]any{
				"project":     map[string]any{"key": j.Project},
				"summary":     iss.Title,
				"description": iss.Body,
				"issuetype":   map[string]any{"name": j.issueType()},
				"labels":      jiraLabels(iss.Labels),
			},
		}
		if err := postJSON(ctx, j.HTTP, url, payload, func(req *http.Request) {
			req.Header.Set("Authorization", "Basic "+auth)
		}); err != nil {
			return created, err
		}
		created++
	}
	return created, nil
}

// jiraLabels sanitizes labels: Jira forbids spaces in label values.
func jiraLabels(labels []string) []string {
	out := make([]string, 0, len(labels))
	for _, l := range labels {
		out = append(out, strings.ReplaceAll(l, " ", "_"))
	}
	return out
}

// postJSON sends a JSON POST and treats any non-2xx as an error. The decorate
// callback sets request-specific headers (auth, accept).
func postJSON(ctx context.Context, client *http.Client, url string, payload any, decorate func(*http.Request)) error {
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal issue: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	decorate(req)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, readErr := io.ReadAll(io.LimitReader(resp.Body, 512))
		if readErr != nil {
			snippet = nil
		}
		return fmt.Errorf("tracker API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}

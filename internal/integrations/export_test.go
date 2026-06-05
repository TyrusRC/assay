package integrations

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
)

func twoIssues() []Issue {
	return BuildIssues(core.Findings{
		mkF("first", core.SeverityHigh),
		mkF("second", core.SeverityCritical),
	}, core.SeverityLow)
}

func readJSONBody(t *testing.T, r io.Reader) map[string]any {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	m := map[string]any{}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("unmarshal body: %v", err)
		}
	}
	return m
}

func writeCreated(t *testing.T, w http.ResponseWriter, body string) {
	t.Helper()
	w.WriteHeader(http.StatusCreated)
	if _, err := w.Write([]byte(body)); err != nil {
		t.Errorf("write: %v", err)
	}
}

func TestGitHubExporter_CreatesIssues(t *testing.T) {
	var gotAuth, gotPath string
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		bodies = append(bodies, readJSONBody(t, r.Body))
		writeCreated(t, w, `{"number":1,"html_url":"https://github.com/o/r/issues/1"}`)
	}))
	defer srv.Close()

	ex := &GitHubExporter{Repo: "owner/repo", Token: "ghtok", BaseURL: srv.URL, HTTP: srv.Client()}
	n, err := ex.Export(context.Background(), twoIssues())
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 created, got %d", n)
	}
	if gotAuth != "Bearer ghtok" {
		t.Errorf("expected bearer auth, got %q", gotAuth)
	}
	if gotPath != "/repos/owner/repo/issues" {
		t.Errorf("unexpected path %q", gotPath)
	}
	if _, ok := bodies[0]["title"]; !ok {
		t.Error("payload missing title")
	}
}

func TestGitHubExporter_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		if _, err := w.Write([]byte(`{"message":"Validation Failed"}`)); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()

	ex := &GitHubExporter{Repo: "owner/repo", Token: "t", BaseURL: srv.URL, HTTP: srv.Client()}
	_, err := ex.Export(context.Background(), twoIssues())
	if err == nil {
		t.Fatal("expected an error on 422 response")
	}
}

func TestGitHubExporter_Validate(t *testing.T) {
	ex := &GitHubExporter{}
	if err := ex.Validate(); err == nil {
		t.Error("expected validation error without repo/token")
	}
	ex = &GitHubExporter{Repo: "o/r", Token: "t"}
	if err := ex.Validate(); err != nil {
		t.Errorf("valid config should pass: %v", err)
	}
	if !strings.Contains(ex.base(), "api.github.com") {
		t.Errorf("default base should be api.github.com, got %q", ex.base())
	}
}

func TestJiraExporter_CreatesIssues(t *testing.T) {
	var gotAuth, gotPath string
	var payload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		payload = readJSONBody(t, r.Body)
		writeCreated(t, w, `{"key":"SEC-1"}`)
	}))
	defer srv.Close()

	ex := &JiraExporter{BaseURL: srv.URL, Project: "SEC", Email: "me@x.io", Token: "jt", HTTP: srv.Client()}
	n, err := ex.Export(context.Background(), twoIssues()[:1])
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 created, got %d", n)
	}
	if !strings.HasPrefix(gotAuth, "Basic ") {
		t.Errorf("Jira Cloud uses basic auth, got %q", gotAuth)
	}
	if gotPath != "/rest/api/2/issue" {
		t.Errorf("unexpected path %q", gotPath)
	}
	fields, ok := payload["fields"].(map[string]any)
	if !ok || fields == nil {
		t.Fatal("payload missing fields object")
	}
	proj, ok := fields["project"].(map[string]any)
	if !ok || proj == nil || proj["key"] != "SEC" {
		t.Errorf("expected project key SEC, got %v", fields["project"])
	}
}

func TestJiraExporter_Validate(t *testing.T) {
	if err := (&JiraExporter{}).Validate(); err == nil {
		t.Error("expected validation error without config")
	}
	ok := &JiraExporter{BaseURL: "https://x.atlassian.net", Project: "SEC", Email: "a@b.c", Token: "t"}
	if err := ok.Validate(); err != nil {
		t.Errorf("valid config should pass: %v", err)
	}
}

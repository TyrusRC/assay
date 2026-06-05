package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/scanner"
)

// fakeRunner returns a canned result (or error) without touching the network.
type fakeRunner struct {
	result *scanner.ScanResult
	err    error
}

func (f fakeRunner) Run(_ context.Context, req ScanRequest) (*scanner.ScanResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	res := f.result
	if res == nil {
		res = &scanner.ScanResult{Targets: []string{req.Target}}
	}
	return res, nil
}

func sampleResult() *scanner.ScanResult {
	f := core.NewFinding("SQL Injection", core.SeverityCritical)
	f.URL = "https://example.com/?id=1"
	f.CWE = []string{"CWE-89"}
	return &scanner.ScanResult{
		Targets:  []string{"https://example.com"},
		Findings: core.Findings{f},
	}
}

func decodeJob(t *testing.T, rec *httptest.ResponseRecorder) ScanJob {
	t.Helper()
	var job ScanJob
	if err := json.Unmarshal(rec.Body.Bytes(), &job); err != nil {
		t.Fatalf("decode job: %v", err)
	}
	return job
}

func doJSON(t *testing.T, srv *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, http.NoBody)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, r)
	return rec
}

func TestHealth(t *testing.T) {
	srv := NewServer(fakeRunner{})
	rec := doJSON(t, srv, http.MethodGet, "/api/health", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("health code = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Errorf("health body = %q", rec.Body.String())
	}
}

func TestCreateScan_LifecycleCompletes(t *testing.T) {
	srv := NewServer(fakeRunner{result: sampleResult()})

	rec := doJSON(t, srv, http.MethodPost, "/api/scans", `{"target":"https://example.com"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("create code = %d, want 202; body=%s", rec.Code, rec.Body.String())
	}
	var job ScanJob
	if err := json.Unmarshal(rec.Body.Bytes(), &job); err != nil {
		t.Fatalf("decode job: %v", err)
	}
	if job.ID == "" || job.Status != StatusQueued {
		t.Fatalf("job = %+v, want id + queued", job)
	}

	srv.WaitIdle() // let the async scan finish

	got, _ := srv.store.Get(job.ID)
	if got.Status != StatusCompleted {
		t.Fatalf("status = %q, want completed", got.Status)
	}
	if got.Summary == nil || got.Summary.Critical != 1 {
		t.Errorf("summary = %+v, want 1 critical", got.Summary)
	}
}

func TestCreateScan_Validation(t *testing.T) {
	srv := NewServer(fakeRunner{})
	if rec := doJSON(t, srv, http.MethodPost, "/api/scans", `{"target":""}`); rec.Code != http.StatusBadRequest {
		t.Errorf("empty target code = %d, want 400", rec.Code)
	}
	if rec := doJSON(t, srv, http.MethodPost, "/api/scans", `{not json`); rec.Code != http.StatusBadRequest {
		t.Errorf("bad json code = %d, want 400", rec.Code)
	}
}

func TestCreateScan_RunnerFailure(t *testing.T) {
	srv := NewServer(fakeRunner{err: errors.New("boom")})
	rec := doJSON(t, srv, http.MethodPost, "/api/scans", `{"target":"https://example.com"}`)
	job := decodeJob(t, rec)
	srv.WaitIdle()
	got, _ := srv.store.Get(job.ID)
	if got.Status != StatusFailed || got.Error == "" {
		t.Errorf("job = %+v, want failed with error", got)
	}
}

func TestListAndGetScan(t *testing.T) {
	srv := NewServer(fakeRunner{result: sampleResult()})
	rec := doJSON(t, srv, http.MethodPost, "/api/scans", `{"target":"https://example.com"}`)
	job := decodeJob(t, rec)
	srv.WaitIdle()

	list := doJSON(t, srv, http.MethodGet, "/api/scans", "")
	var jobs []ScanJob
	if err := json.Unmarshal(list.Body.Bytes(), &jobs); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("list len = %d, want 1", len(jobs))
	}

	if rec := doJSON(t, srv, http.MethodGet, "/api/scans/"+job.ID, ""); rec.Code != http.StatusOK {
		t.Errorf("get code = %d, want 200", rec.Code)
	}
	if rec := doJSON(t, srv, http.MethodGet, "/api/scans/nope", ""); rec.Code != http.StatusNotFound {
		t.Errorf("missing get code = %d, want 404", rec.Code)
	}
}

func TestGetReport(t *testing.T) {
	srv := NewServer(fakeRunner{result: sampleResult()})
	rec := doJSON(t, srv, http.MethodPost, "/api/scans", `{"target":"https://example.com"}`)
	job := decodeJob(t, rec)
	srv.WaitIdle()

	// JSON report (default).
	rj := doJSON(t, srv, http.MethodGet, "/api/scans/"+job.ID+"/report", "")
	if rj.Code != http.StatusOK || !strings.Contains(rj.Body.String(), "SQL Injection") {
		t.Errorf("json report code=%d body=%s", rj.Code, rj.Body.String())
	}
	if ct := rj.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("json content-type = %q", ct)
	}

	// SARIF report.
	rs := doJSON(t, srv, http.MethodGet, "/api/scans/"+job.ID+"/report?format=sarif", "")
	if rs.Code != http.StatusOK || !strings.Contains(rs.Body.String(), "2.1.0") {
		t.Errorf("sarif report code=%d body=%s", rs.Code, rs.Body.String())
	}

	// Unknown format.
	if ru := doJSON(t, srv, http.MethodGet, "/api/scans/"+job.ID+"/report?format=bogus", ""); ru.Code != http.StatusBadRequest {
		t.Errorf("bogus format code = %d, want 400", ru.Code)
	}
}

func TestGetReport_NotCompleted(t *testing.T) {
	// Block the runner so the scan stays running while we query the report.
	release := make(chan struct{})
	srv := NewServer(blockingRunner{release: release})
	rec := doJSON(t, srv, http.MethodPost, "/api/scans", `{"target":"https://example.com"}`)
	job := decodeJob(t, rec)

	rr := doJSON(t, srv, http.MethodGet, "/api/scans/"+job.ID+"/report", "")
	if rr.Code != http.StatusConflict {
		t.Errorf("report-while-running code = %d, want 409", rr.Code)
	}
	close(release)
	srv.WaitIdle()
}

// blockingRunner waits on release before returning, so a scan can be observed
// mid-flight.
type blockingRunner struct{ release chan struct{} }

func (b blockingRunner) Run(_ context.Context, req ScanRequest) (*scanner.ScanResult, error) {
	<-b.release
	return &scanner.ScanResult{Targets: []string{req.Target}}, nil
}

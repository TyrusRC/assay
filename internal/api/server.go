package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/TyrusRC/assay/internal/reporting"
	"github.com/TyrusRC/assay/internal/scanner"
)

// Runner executes a scan for a request and returns its result. Implementations
// back the real scanner; tests supply a fake.
type Runner interface {
	Run(ctx context.Context, req ScanRequest) (*scanner.ScanResult, error)
}

// scanTimeout bounds a single API-triggered scan.
const scanTimeout = 30 * time.Minute

// Server is the HTTP JSON API for scans.
type Server struct {
	store  *Store
	runner Runner
	mux    *http.ServeMux
	wg     sync.WaitGroup
}

// NewServer builds a Server backed by runner. The returned Server's Handler
// also serves any provided static frontend.
func NewServer(runner Runner) *Server {
	s := &Server{
		store:  NewStore(),
		runner: runner,
		mux:    http.NewServeMux(),
	}
	s.routes()
	return s
}

// Handler returns the HTTP handler for the API (without the static frontend).
func (s *Server) Handler() http.Handler {
	return s.mux
}

// WaitIdle blocks until all in-flight scans finish. Intended for tests and
// graceful shutdown.
func (s *Server) WaitIdle() {
	s.wg.Wait()
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
	s.mux.HandleFunc("POST /api/scans", s.handleCreateScan)
	s.mux.HandleFunc("GET /api/scans", s.handleListScans)
	s.mux.HandleFunc("GET /api/scans/{id}", s.handleGetScan)
	s.mux.HandleFunc("GET /api/scans/{id}/report", s.handleGetReport)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	req.Target = strings.TrimSpace(req.Target)
	if req.Target == "" {
		writeError(w, http.StatusBadRequest, "target is required")
		return
	}

	job := s.store.Create(req)
	s.start(r.Context(), job.ID, req)
	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) handleListScans(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.store.List())
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	job, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) handleGetReport(w http.ResponseWriter, r *http.Request) {
	job, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	if job.Status != StatusCompleted || job.result == nil {
		writeError(w, http.StatusConflict, "scan has not completed")
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	contentType, ok := reportContentType(format)
	if !ok {
		writeError(w, http.StatusBadRequest, "unknown report format: "+format)
		return
	}
	report := reporting.NewReport(job.result)
	w.Header().Set("Content-Type", contentType)
	if err := writeReport(w, report, format); err != nil {
		// Headers are already sent; nothing more we can safely do.
		return
	}
}

// start launches the scan asynchronously, transitioning job state as it runs.
// The scan derives from the request context for request-scoped values but is
// detached from its cancellation so it survives the HTTP response returning.
func (s *Server) start(reqCtx context.Context, id string, req ScanRequest) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.store.setRunning(id)
		ctx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), scanTimeout)
		defer cancel()
		result, err := s.runner.Run(ctx, req)
		if err != nil {
			s.store.setFailed(id, err.Error())
			return
		}
		s.store.setCompleted(id, result)
	}()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return // response already partially written; best effort
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

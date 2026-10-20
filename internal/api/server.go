package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strconv"
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

// maxConcurrentScans limits how many API-triggered scans can run in parallel.
const maxConcurrentScans = 3

// ServerConfig holds options for building a Server.
type ServerConfig struct {
	// APIKey, when non-empty, requires a Bearer token on authenticated endpoints.
	APIKey string
	// AllowPrivateTargets disables the SSRF protection that blocks scans against
	// private/link-local IP addresses. Intended for internal-network scanners.
	AllowPrivateTargets bool
}

// Server is the HTTP JSON API for scans.
type Server struct {
	store   *Store
	runner  Runner
	mux     *http.ServeMux
	wg      sync.WaitGroup
	scanSem chan struct{}
	config  ServerConfig
}

// NewServer builds a Server backed by runner. The returned Server's Handler
// also serves any provided static frontend.
func NewServer(runner Runner) *Server {
	return NewServerWithStore(runner, NewStore(), ServerConfig{})
}

// NewServerWithStore builds a Server backed by runner and a caller-provided
// store — pass a persistent store so jobs survive a restart.
func NewServerWithStore(runner Runner, store *Store, cfg ServerConfig) *Server {
	s := &Server{
		store:   store,
		runner:  runner,
		mux:     http.NewServeMux(),
		scanSem: make(chan struct{}, maxConcurrentScans),
		config:  cfg,
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
	s.mux.HandleFunc("POST /api/scans", s.requireAuth(s.handleCreateScan))
	s.mux.HandleFunc("GET /api/scans", s.requireAuth(s.handleListScans))
	s.mux.HandleFunc("GET /api/scans/{id}", s.requireAuth(s.handleGetScan))
	s.mux.HandleFunc("GET /api/scans/{id}/report", s.requireAuth(s.handleGetReport))
}

// requireAuth wraps a handler with bearer-token checking when an API key is
// configured. Health is left open so load balancers can probe without a key.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.config.APIKey != "" {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") || strings.TrimPrefix(auth, "Bearer ") != s.config.APIKey {
				writeError(w, http.StatusUnauthorized, "missing or invalid API key")
				return
			}
		}
		next(w, r)
	}
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

	if err := s.validateTarget(req.Target); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	job := s.store.Create(req)
	s.start(r.Context(), job.ID, req)
	writeJSON(w, http.StatusAccepted, job)
}

// validateTarget checks the scan target for scheme and SSRF safety.
func (s *Server) validateTarget(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return &validationError{"invalid target URL (must include scheme and host)"}
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return &validationError{"unsupported scheme: only http and https are allowed"}
	}
	if s.config.AllowPrivateTargets {
		return nil
	}
	host := u.Hostname()
	ips, err := net.LookupHost(host)
	if err != nil {
		return &validationError{"cannot resolve target host"}
	}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return &validationError{"target resolves to a private/loopback address"}
		}
	}
	return nil
}

type validationError struct{ msg string }

func (e *validationError) Error() string { return e.msg }

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	offset, limit := parsePagination(r)
	writeJSON(w, http.StatusOK, s.store.ListPaged(offset, limit))
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
// A bounded semaphore limits concurrent scans.
func (s *Server) start(reqCtx context.Context, id string, req ScanRequest) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		// Acquire a scan slot — fail the job if none are available within a
		// short window so callers get immediate feedback instead of an
		// unbounded queue.
		select {
		case s.scanSem <- struct{}{}:
			defer func() { <-s.scanSem }()
		case <-time.After(5 * time.Second):
			s.store.setFailed(id, "too many concurrent scans; try again later")
			return
		}

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

// parsePagination extracts offset and limit query parameters. Defaults: offset=0, limit=100.
func parsePagination(r *http.Request) (offset, limit int) {
	offset = queryInt(r, "offset", 0)
	limit = queryInt(r, "limit", 100)
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	return
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

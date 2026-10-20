package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TyrusRC/assay/internal/reporting"
	"github.com/TyrusRC/assay/internal/scanner"
)

func logInfo(msg string, args ...any)  { fmt.Fprintf(os.Stderr, "[INFO] "+msg+"\n", args...) }
func logWarn(msg string, args ...any)  { fmt.Fprintf(os.Stderr, "[WARN] "+msg+"\n", args...) }
func logError(msg string, args ...any) { fmt.Fprintf(os.Stderr, "[ERROR] "+msg+"\n", args...) }

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
	s.mux.HandleFunc("DELETE /api/scans/{id}", s.requireAuth(s.handleCancelScan))
	s.mux.HandleFunc("GET /api/scans/{id}/progress", s.requireAuth(s.handleGetProgress))
	s.mux.HandleFunc("GET /api/scans/{id}/report", s.requireAuth(s.handleGetReport))
}

// requireAuth wraps a handler with bearer-token checking when an API key is
// configured. Health is left open so load balancers can probe without a key.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.config.APIKey != "" {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				writeError(w, http.StatusUnauthorized, "missing or invalid API key")
				return
			}
			got := strings.TrimPrefix(auth, "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(s.config.APIKey)) != 1 {
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
	logInfo("scan %s queued for %s", job.ID, req.Target)
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
		if isBlockedIP(ipStr) {
			return &validationError{"target resolves to a private/loopback address"}
		}
	}
	return nil
}

// isBlockedIP reports whether ipStr is a loopback, private, link-local, or
// unspecified address. IPv6-mapped IPv4 addresses (e.g. ::ffff:127.0.0.1) are
// normalised to their IPv4 form first so they cannot bypass the check.
func isBlockedIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true // unparseable → block
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// SafeDialContext returns a net.Dialer.DialContext wrapper that resolves the
// target address and blocks connections to private/loopback IPs. Use it as the
// DialContext in an http.Transport to defend against DNS-rebinding SSRF: even
// if a hostname resolved to a public IP at validation time, the transport-level
// check catches a rebind to a private IP at connect time.
func SafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("ssrf dial: %w", err)
	}
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("ssrf dial: resolve %s: %w", host, err)
	}
	for _, ipStr := range ips {
		if isBlockedIP(ipStr) {
			return nil, fmt.Errorf("ssrf dial: %s resolved to blocked address %s", host, ipStr)
		}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0], port))
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

func (s *Server) handleCancelScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.store.Get(id); !ok {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	if !s.store.Cancel(id) {
		writeError(w, http.StatusConflict, "scan is not running")
		return
	}
	logInfo("scan %s cancelled by operator", id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

func (s *Server) handleGetProgress(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := s.store.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	if job.Status != StatusRunning {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":   job.Status,
			"progress": job.Progress,
		})
		return
	}
	p := s.store.GetProgress(id)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   job.Status,
		"progress": p,
	})
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
			logWarn("scan %s rejected: too many concurrent scans", id)
			s.store.setFailed(id, "too many concurrent scans; try again later")
			return
		}

		s.store.setRunning(id)
		ctx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), scanTimeout)
		defer cancel()
		s.store.setCancel(id, cancel)

		logInfo("scan %s started for %s (profile=%s)", id, req.Target, req.Profile)

		result, err := s.runner.Run(ctx, req)
		if ctx.Err() != nil {
			logInfo("scan %s cancelled", id)
			return
		}
		if err != nil {
			logError("scan %s failed: %v", id, err)
			s.store.setFailed(id, err.Error())
			return
		}
		summary := result.Summary()
		s.store.setProgress(id, ScanProgress{
			Phase:         "completed",
			FindingsCount: summary.TotalFindings,
		})
		logInfo("scan %s completed: %d findings", id, summary.TotalFindings)
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

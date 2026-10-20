package api

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/TyrusRC/assay/internal/scanner"
)

// ScanStatus is the lifecycle state of a scan job.
type ScanStatus string

const (
	// StatusQueued means the job is created but not yet started.
	StatusQueued ScanStatus = "queued"
	// StatusRunning means the scan is in progress.
	StatusRunning ScanStatus = "running"
	// StatusCompleted means the scan finished successfully.
	StatusCompleted ScanStatus = "completed"
	// StatusFailed means the scan errored out.
	StatusFailed ScanStatus = "failed"
	// StatusCancelled means the scan was stopped by the operator.
	StatusCancelled ScanStatus = "cancelled"
)

// ScanProgress holds live scan metrics exposed via the progress endpoint.
type ScanProgress struct {
	Phase         string `json:"phase"`
	FindingsCount int    `json:"findings_count"`
	RequestsSent  int    `json:"requests_sent"`
}

// DefaultMaxJobs is the default upper bound on stored jobs before eviction.
const DefaultMaxJobs = 1000

// ScanRequest is the payload to start a scan.
type ScanRequest struct {
	Target  string `json:"target"`
	Profile string `json:"profile,omitempty"`
}

// ScanJob tracks one scan's lifecycle and (when finished) its result.
type ScanJob struct {
	ID        string               `json:"id"`
	Target    string               `json:"target"`
	Profile   string               `json:"profile,omitempty"`
	Status    ScanStatus           `json:"status"`
	Error     string               `json:"error,omitempty"`
	Summary   *scanner.ScanSummary `json:"summary,omitempty"`
	Progress  *ScanProgress        `json:"progress,omitempty"`
	CreatedAt time.Time            `json:"created_at"`
	UpdatedAt time.Time            `json:"updated_at"`

	// result holds the raw scan output for report rendering. It is not
	// serialized in the job listing; reports are fetched via their endpoint.
	result *scanner.ScanResult
	// cancel, when non-nil, stops the running scan's context.
	cancel context.CancelFunc
}

// Result returns the raw scan result, or nil if the scan has not completed.
func (j *ScanJob) Result() *scanner.ScanResult {
	return j.result
}

// Store is a concurrency-safe registry of scan jobs. When path is non-empty the
// job metadata is persisted to disk after each change, so `assay serve` survives
// a restart (the in-memory raw result is not persisted — status, summary and
// listing are).
type Store struct {
	mu      sync.RWMutex
	jobs    map[string]*ScanJob
	order   []string
	now     func() time.Time
	path    string
	maxJobs int
}

// NewStore creates an empty in-memory job store.
func NewStore() *Store {
	return &Store{
		jobs:    make(map[string]*ScanJob),
		now:     time.Now,
		maxJobs: DefaultMaxJobs,
	}
}

// NewPersistentStore creates a job store backed by a JSON file at path. Existing
// jobs are loaded; subsequent changes are written back. A missing file is not an
// error (a fresh store).
func NewPersistentStore(path string) (*Store, error) {
	s := &Store{
		jobs:    make(map[string]*ScanJob),
		now:     time.Now,
		path:    path,
		maxJobs: DefaultMaxJobs,
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// persisted is the on-disk shape of the store.
type persisted struct {
	Order []string            `json:"order"`
	Jobs  map[string]*ScanJob `json:"jobs"`
}

// load reads the backing file into the store. A missing file is ignored.
func (s *Store) load() error {
	if s.path == "" {
		return nil
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("api: read job store %s: %w", s.path, err)
	}
	if len(data) == 0 {
		return nil
	}
	var p persisted
	if err := json.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("api: parse job store %s: %w", s.path, err)
	}
	if p.Jobs != nil {
		s.jobs = p.Jobs
	}
	s.order = p.Order
	return nil
}

// persistLocked writes the store to disk atomically. The caller holds s.mu.
// NOTE: the write happens under the lock, so job mutations serialize on disk IO;
// fine for serve's job volume. Raise to an async writer if that ever bites.
func (s *Store) persistLocked() error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(persisted{Order: s.order, Jobs: s.jobs}, "", "  ")
	if err != nil {
		return fmt.Errorf("api: marshal job store: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("api: create job store dir: %w", err)
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("api: write job store tmp: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("api: rename job store: %w", err)
	}
	return nil
}

// logPersist calls persistLocked and logs the error to stderr (most callers
// cannot propagate a persist failure up the call chain).
func (s *Store) logPersist() {
	if err := s.persistLocked(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
	}
}

// evictLocked removes the oldest completed or failed jobs until the store is
// within its maxJobs limit. The caller holds s.mu.
func (s *Store) evictLocked() {
	for len(s.order) > s.maxJobs {
		evicted := false
		for i, id := range s.order {
			job := s.jobs[id]
			if job.Status == StatusCompleted || job.Status == StatusFailed {
				delete(s.jobs, id)
				s.order = append(s.order[:i], s.order[i+1:]...)
				evicted = true
				break
			}
		}
		if !evicted {
			break // only queued/running jobs remain — don't evict those
		}
	}
}

// Create registers a new queued job for the request and returns a copy.
func (s *Store) Create(req ScanRequest) *ScanJob {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	job := &ScanJob{
		ID:        uuid.NewString(),
		Target:    req.Target,
		Profile:   req.Profile,
		Status:    StatusQueued,
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.jobs[job.ID] = job
	s.order = append(s.order, job.ID)
	s.evictLocked()
	s.logPersist()
	return copyJob(job)
}

// Get returns a copy of the job and whether it exists.
func (s *Store) Get(id string) (*ScanJob, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	job, ok := s.jobs[id]
	if !ok {
		return nil, false
	}
	return copyJob(job), true
}

// List returns copies of all jobs in creation order (newest last).
func (s *Store) List() []*ScanJob {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*ScanJob, 0, len(s.order))
	for _, id := range s.order {
		out = append(out, copyJob(s.jobs[id]))
	}
	return out
}

// ListPaged returns a paginated slice of jobs in creation order.
func (s *Store) ListPaged(offset, limit int) []*ScanJob {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if offset >= len(s.order) {
		return []*ScanJob{}
	}
	end := offset + limit
	if end > len(s.order) {
		end = len(s.order)
	}
	out := make([]*ScanJob, 0, end-offset)
	for _, id := range s.order[offset:end] {
		out = append(out, copyJob(s.jobs[id]))
	}
	return out
}

// setRunning transitions a job to running.
func (s *Store) setRunning(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if job, ok := s.jobs[id]; ok {
		job.Status = StatusRunning
		job.UpdatedAt = s.now()
		s.logPersist()
	}
}

// setCompleted stores the result and summary and marks the job completed.
func (s *Store) setCompleted(id string, result *scanner.ScanResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if job, ok := s.jobs[id]; ok {
		job.Status = StatusCompleted
		job.result = result
		summary := result.Summary()
		job.Summary = &summary
		job.UpdatedAt = s.now()
		s.logPersist()
	}
}

// setFailed marks the job failed with the given error message.
func (s *Store) setFailed(id, errMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if job, ok := s.jobs[id]; ok {
		job.Status = StatusFailed
		job.Error = errMsg
		job.UpdatedAt = s.now()
		s.logPersist()
	}
}

// setCancel stores the cancel function for a running job so the API can stop it.
func (s *Store) setCancel(id string, cancel context.CancelFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if job, ok := s.jobs[id]; ok {
		job.cancel = cancel
	}
}

// Cancel cancels a running scan and marks it cancelled. Returns true if the
// job was running and is now cancelled; false otherwise.
func (s *Store) Cancel(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[id]
	if !ok || job.Status != StatusRunning {
		return false
	}
	if job.cancel != nil {
		job.cancel()
	}
	job.Status = StatusCancelled
	job.UpdatedAt = s.now()
	s.logPersist()
	return true
}

// setProgress updates the live progress metrics for a running job.
func (s *Store) setProgress(id string, p ScanProgress) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if job, ok := s.jobs[id]; ok && job.Status == StatusRunning {
		job.Progress = &p
	}
}

// GetProgress returns the live progress for a job, or nil.
func (s *Store) GetProgress(id string) *ScanProgress {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if job, ok := s.jobs[id]; ok && job.Progress != nil {
		cp := *job.Progress
		return &cp
	}
	return nil
}

// copyJob returns a shallow copy safe to hand out without exposing the stored
// pointer. The result pointer is shared (read-only once completed).
func copyJob(j *ScanJob) *ScanJob {
	cp := *j
	return &cp
}

package api

import (
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
)

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
	CreatedAt time.Time            `json:"created_at"`
	UpdatedAt time.Time            `json:"updated_at"`

	// result holds the raw scan output for report rendering. It is not
	// serialized in the job listing; reports are fetched via their endpoint.
	result *scanner.ScanResult
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
	mu    sync.RWMutex
	jobs  map[string]*ScanJob
	order []string
	now   func() time.Time
	path  string
}

// NewStore creates an empty in-memory job store.
func NewStore() *Store {
	return &Store{
		jobs: make(map[string]*ScanJob),
		now:  time.Now,
	}
}

// NewPersistentStore creates a job store backed by a JSON file at path. Existing
// jobs are loaded; subsequent changes are written back. A missing file is not an
// error (a fresh store).
func NewPersistentStore(path string) (*Store, error) {
	s := &Store{
		jobs: make(map[string]*ScanJob),
		now:  time.Now,
		path: path,
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
func (s *Store) persistLocked() {
	if s.path == "" {
		return
	}
	data, err := json.MarshalIndent(persisted{Order: s.order, Jobs: s.jobs}, "", "  ")
	if err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, s.path)
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
	s.persistLocked()
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

// setRunning transitions a job to running.
func (s *Store) setRunning(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if job, ok := s.jobs[id]; ok {
		job.Status = StatusRunning
		job.UpdatedAt = s.now()
		s.persistLocked()
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
		s.persistLocked()
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
		s.persistLocked()
	}
}

// copyJob returns a shallow copy safe to hand out without exposing the stored
// pointer. The result pointer is shared (read-only once completed).
func copyJob(j *ScanJob) *ScanJob {
	cp := *j
	return &cp
}

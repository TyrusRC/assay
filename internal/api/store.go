package api

import (
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

// Store is a concurrency-safe in-memory registry of scan jobs.
type Store struct {
	mu    sync.RWMutex
	jobs  map[string]*ScanJob
	order []string
	now   func() time.Time
}

// NewStore creates an empty job store.
func NewStore() *Store {
	return &Store{
		jobs: make(map[string]*ScanJob),
		now:  time.Now,
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
	}
}

// copyJob returns a shallow copy safe to hand out without exposing the stored
// pointer. The result pointer is shared (read-only once completed).
func copyJob(j *ScanJob) *ScanJob {
	cp := *j
	return &cp
}

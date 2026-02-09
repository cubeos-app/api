package managers

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// JobStatus represents the lifecycle state of a job
type JobStatus string

const (
	JobPending   JobStatus = "pending"
	JobRunning   JobStatus = "running"
	JobCompleted JobStatus = "completed"
	JobFailed    JobStatus = "failed"
)

// ProgressEvent is a single SSE event streamed to the frontend
type ProgressEvent struct {
	Step     string `json:"step"`            // e.g. "validate", "deploy", "dns"
	Progress int    `json:"progress"`        // 0-100
	Detail   string `json:"detail"`          // Human-readable message
	Status   string `json:"status"`          // "running", "done", "error"
	Error    string `json:"error,omitempty"` // Error message (only on failure)
}

// Job represents an async install/uninstall operation
type Job struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // "install" or "uninstall"
	AppName   string    `json:"app_name"`
	Status    JobStatus `json:"status"`
	Progress  int       `json:"progress"`
	Events    chan ProgressEvent
	CreatedAt time.Time `json:"created_at"`
	mu        sync.RWMutex
}

// SetStatus updates the job status (thread-safe)
func (j *Job) SetStatus(status JobStatus) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Status = status
}

// GetStatus returns the current job status (thread-safe)
func (j *Job) GetStatus() JobStatus {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.Status
}

// GetProgress returns the current progress percentage (thread-safe)
func (j *Job) GetProgress() int {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.Progress
}

// Emit sends a progress event to the SSE channel (non-blocking).
// If the channel buffer is full, the event is dropped with a warning.
func (j *Job) Emit(step string, progress int, detail string) {
	j.mu.Lock()
	j.Progress = progress
	j.mu.Unlock()

	event := ProgressEvent{
		Step:     step,
		Progress: progress,
		Detail:   detail,
		Status:   "running",
	}

	select {
	case j.Events <- event:
	default:
		log.Warn().Str("job", j.ID).Str("step", step).Msg("SSE event channel full, dropping event")
	}
}

// EmitError sends an error event and closes the channel
func (j *Job) EmitError(step string, progress int, errMsg string) {
	j.SetStatus(JobFailed)

	event := ProgressEvent{
		Step:     step,
		Progress: progress,
		Detail:   errMsg,
		Status:   "error",
		Error:    errMsg,
	}

	select {
	case j.Events <- event:
	default:
	}
}

// EmitDone sends the final "complete" event and closes the channel
func (j *Job) EmitDone(detail string) {
	j.SetStatus(JobCompleted)

	event := ProgressEvent{
		Step:     "complete",
		Progress: 100,
		Detail:   detail,
		Status:   "done",
	}

	select {
	case j.Events <- event:
	default:
	}
}

// Close closes the events channel. Must be called exactly once
// when the job goroutine finishes (success or failure).
func (j *Job) Close() {
	close(j.Events)
}

// JobTracker manages all active async jobs
type JobTracker struct {
	jobs map[string]*Job
	mu   sync.RWMutex
}

// NewJobTracker creates a new job tracker
func NewJobTracker() *JobTracker {
	return &JobTracker{
		jobs: make(map[string]*Job),
	}
}

// CreateJob creates and registers a new job
func (jt *JobTracker) CreateJob(jobType, appName string) *Job {
	id := generateJobID()
	job := &Job{
		ID:        id,
		Type:      jobType,
		AppName:   appName,
		Status:    JobPending,
		Events:    make(chan ProgressEvent, 32), // buffered to avoid blocking install goroutine
		CreatedAt: time.Now(),
	}

	jt.mu.Lock()
	jt.jobs[id] = job
	jt.mu.Unlock()

	// Auto-cleanup after 5 minutes to prevent memory leaks
	go func() {
		time.Sleep(5 * time.Minute)
		jt.mu.Lock()
		delete(jt.jobs, id)
		jt.mu.Unlock()
		log.Debug().Str("job", id).Msg("job auto-cleaned from tracker")
	}()

	return job
}

// GetJob returns a job by ID, or nil if not found
func (jt *JobTracker) GetJob(id string) *Job {
	jt.mu.RLock()
	defer jt.mu.RUnlock()
	return jt.jobs[id]
}

// generateJobID creates a random hex job ID
func generateJobID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID
		return hex.EncodeToString([]byte(time.Now().Format("20060102150405.000")))
	}
	return hex.EncodeToString(b)
}

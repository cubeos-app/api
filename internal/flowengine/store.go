package flowengine

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// newUUID generates a v4 UUID string using crypto/rand.
// This avoids promoting google/uuid from indirect to direct dependency.
func newUUID() string {
	var u [16]byte
	_, _ = rand.Read(u[:])
	u[6] = (u[6] & 0x0f) | 0x40 // version 4
	u[8] = (u[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// WorkflowRun represents a row in the workflow_runs table.
type WorkflowRun struct {
	ID           string          `json:"id"`
	WorkflowType string          `json:"workflow_type"`
	Version      int             `json:"version"`
	ExternalID   string          `json:"external_id,omitempty"`
	CurrentState WorkflowState   `json:"current_state"`
	CurrentStep  int             `json:"current_step"`
	Input        json.RawMessage `json:"input,omitempty"`
	Output       json.RawMessage `json:"output,omitempty"`
	Error        string          `json:"error,omitempty"`
	Metadata     json.RawMessage `json:"metadata,omitempty"`
	LockedBy     string          `json:"locked_by,omitempty"`
	LockedUntil  *time.Time      `json:"locked_until,omitempty"`
	MaxRetries   int             `json:"max_retries"`
	RetryCount   int             `json:"retry_count"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// WorkflowStep represents a row in the workflow_steps table.
type WorkflowStep struct {
	ID             string          `json:"id"`
	WorkflowID     string          `json:"workflow_id"`
	StepIndex      int             `json:"step_index"`
	StepName       string          `json:"step_name"`
	ActivityName   string          `json:"activity_name"`
	CompensateName string          `json:"compensate_name,omitempty"`
	Status         StepStatus      `json:"status"`
	Input          json.RawMessage `json:"input,omitempty"`
	Output         json.RawMessage `json:"output,omitempty"`
	Error          string          `json:"error,omitempty"`
	StartedAt      *time.Time      `json:"started_at,omitempty"`
	CompletedAt    *time.Time      `json:"completed_at,omitempty"`
}

// WorkflowEvent represents a row in the workflow_events table.
type WorkflowEvent struct {
	ID         int64     `json:"id"`
	WorkflowID string    `json:"workflow_id"`
	StepIndex  *int      `json:"step_index,omitempty"`
	EventType  EventType `json:"event_type"`
	OldState   string    `json:"old_state,omitempty"`
	NewState   string    `json:"new_state,omitempty"`
	Detail     string    `json:"detail,omitempty"`
	NodeID     string    `json:"node_id,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// WorkflowStore provides CRUD operations for workflow data in SQLite.
// All methods are safe for concurrent use (SQLite WAL + busy_timeout handles contention).
type WorkflowStore struct {
	db *sql.DB
}

// NewWorkflowStore creates a new store backed by the given database connection.
// The database must have had migration #16 applied (workflow tables exist).
func NewWorkflowStore(db *sql.DB) *WorkflowStore {
	return &WorkflowStore{db: db}
}

// CreateWorkflowParams holds the parameters for creating a new workflow run.
type CreateWorkflowParams struct {
	WorkflowType string
	Version      int
	ExternalID   string          // for idempotency — e.g., app name
	Input        json.RawMessage // workflow-level input (JSON)
	Metadata     json.RawMessage // extensible JSON bag
	MaxRetries   int
	Steps        []StepDefinition // step definitions to persist
}

// CreateWorkflow inserts a new workflow run and its steps into the database.
// Returns ErrDuplicateWorkflow if an active workflow with the same type + external_id exists.
// The operation is atomic — if step creation fails, the workflow is rolled back.
func (s *WorkflowStore) CreateWorkflow(params CreateWorkflowParams) (*WorkflowRun, error) {
	if params.Version < 1 {
		params.Version = 1
	}
	if params.MaxRetries < 1 {
		params.MaxRetries = 3
	}
	if params.Metadata == nil {
		params.Metadata = json.RawMessage(`{}`)
	}

	workflowID := newUUID()
	now := time.Now().UTC()

	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Insert workflow run
	_, err = tx.Exec(`
		INSERT INTO workflow_runs (id, workflow_type, version, external_id, current_state,
			current_step, input, metadata, max_retries, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)`,
		workflowID, params.WorkflowType, params.Version,
		nullableString(params.ExternalID),
		string(StatePending),
		nullableJSON(params.Input),
		string(params.Metadata),
		params.MaxRetries,
		now, now,
	)
	if err != nil {
		// Check for unique constraint violation (active duplicate)
		if isDuplicateErr(err) {
			return nil, fmt.Errorf("%w: type=%s external_id=%s", ErrDuplicateWorkflow, params.WorkflowType, params.ExternalID)
		}
		return nil, fmt.Errorf("insert workflow: %w", err)
	}

	// Insert steps
	for i, step := range params.Steps {
		stepID := newUUID()
		_, err = tx.Exec(`
			INSERT INTO workflow_steps (id, workflow_id, step_index, step_name,
				activity_name, compensate_name, status)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			stepID, workflowID, i, step.Name,
			step.Action, step.Compensate,
			string(StepPending),
		)
		if err != nil {
			return nil, fmt.Errorf("insert step %d (%s): %w", i, step.Name, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	return &WorkflowRun{
		ID:           workflowID,
		WorkflowType: params.WorkflowType,
		Version:      params.Version,
		ExternalID:   params.ExternalID,
		CurrentState: StatePending,
		CurrentStep:  0,
		Input:        params.Input,
		Metadata:     params.Metadata,
		MaxRetries:   params.MaxRetries,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

// GetWorkflow retrieves a workflow run by ID.
// Returns ErrWorkflowNotFound if the ID doesn't exist.
func (s *WorkflowStore) GetWorkflow(id string) (*WorkflowRun, error) {
	row := s.db.QueryRow(`
		SELECT id, workflow_type, version, external_id, current_state, current_step,
			input, output, error, metadata, locked_by, locked_until,
			max_retries, retry_count, created_at, updated_at
		FROM workflow_runs WHERE id = ?`, id)

	return scanWorkflowRun(row)
}

// GetWorkflowByExternalID retrieves an active workflow by type + external_id.
// Returns nil (not error) if no active workflow matches.
func (s *WorkflowStore) GetWorkflowByExternalID(workflowType, externalID string) (*WorkflowRun, error) {
	row := s.db.QueryRow(`
		SELECT id, workflow_type, version, external_id, current_state, current_step,
			input, output, error, metadata, locked_by, locked_until,
			max_retries, retry_count, created_at, updated_at
		FROM workflow_runs
		WHERE workflow_type = ? AND external_id = ?
			AND current_state NOT IN ('completed', 'failed', 'compensated')
		LIMIT 1`, workflowType, externalID)

	wf, err := scanWorkflowRun(row)
	if err == ErrWorkflowNotFound {
		return nil, nil
	}
	return wf, err
}

// GetWorkflowSteps retrieves all steps for a workflow, ordered by step_index.
func (s *WorkflowStore) GetWorkflowSteps(workflowID string) ([]WorkflowStep, error) {
	rows, err := s.db.Query(`
		SELECT id, workflow_id, step_index, step_name, activity_name, compensate_name,
			status, input, output, error, started_at, completed_at
		FROM workflow_steps
		WHERE workflow_id = ?
		ORDER BY step_index ASC`, workflowID)
	if err != nil {
		return nil, fmt.Errorf("query steps: %w", err)
	}
	defer rows.Close()

	var steps []WorkflowStep
	for rows.Next() {
		step, err := scanWorkflowStep(rows)
		if err != nil {
			return nil, err
		}
		steps = append(steps, *step)
	}
	return steps, rows.Err()
}

// GetIncompleteWorkflows retrieves all workflows that are not in a terminal state.
// Used by the engine on startup to recover in-flight workflows.
func (s *WorkflowStore) GetIncompleteWorkflows() ([]WorkflowRun, error) {
	rows, err := s.db.Query(`
		SELECT id, workflow_type, version, external_id, current_state, current_step,
			input, output, error, metadata, locked_by, locked_until,
			max_retries, retry_count, created_at, updated_at
		FROM workflow_runs
		WHERE current_state IN ('pending', 'running', 'compensating')
		ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("query incomplete: %w", err)
	}
	defer rows.Close()

	var workflows []WorkflowRun
	for rows.Next() {
		wf, err := scanWorkflowRunFromRows(rows)
		if err != nil {
			return nil, err
		}
		workflows = append(workflows, *wf)
	}
	return workflows, rows.Err()
}

// UpdateWorkflowState atomically updates the workflow's state and current_step.
// Returns ErrWorkflowNotFound if the workflow doesn't exist.
func (s *WorkflowStore) UpdateWorkflowState(id string, state WorkflowState, currentStep int) error {
	res, err := s.db.Exec(`
		UPDATE workflow_runs
		SET current_state = ?, current_step = ?, updated_at = ?
		WHERE id = ?`,
		string(state), currentStep, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("update workflow state: %w", err)
	}
	return checkRowsAffected(res, id)
}

// UpdateWorkflowOutput sets the final output and state on a workflow.
func (s *WorkflowStore) UpdateWorkflowOutput(id string, state WorkflowState, output json.RawMessage) error {
	res, err := s.db.Exec(`
		UPDATE workflow_runs
		SET current_state = ?, output = ?, updated_at = ?
		WHERE id = ?`,
		string(state), nullableJSON(output), time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("update workflow output: %w", err)
	}
	return checkRowsAffected(res, id)
}

// UpdateWorkflowError sets the error message and failed state on a workflow.
func (s *WorkflowStore) UpdateWorkflowError(id string, state WorkflowState, errMsg string) error {
	res, err := s.db.Exec(`
		UPDATE workflow_runs
		SET current_state = ?, error = ?, updated_at = ?
		WHERE id = ?`,
		string(state), errMsg, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("update workflow error: %w", err)
	}
	return checkRowsAffected(res, id)
}

// UpdateStepStatus atomically transitions a step from expectedStatus to newStatus.
// Returns ErrStepTransitionDenied if the current status doesn't match expectedStatus
// (indicates concurrent modification).
func (s *WorkflowStore) UpdateStepStatus(stepID string, expectedStatus, newStatus StepStatus) error {
	now := time.Now().UTC()

	res, err := s.db.Exec(`
		UPDATE workflow_steps
		SET status = ?,
			started_at = CASE WHEN ? = 'running' AND started_at IS NULL THEN ? ELSE started_at END,
			completed_at = CASE WHEN ? IN ('completed', 'failed', 'compensated') THEN ? ELSE completed_at END
		WHERE id = ? AND status = ?`,
		string(newStatus),
		string(newStatus), now,
		string(newStatus), now,
		stepID, string(expectedStatus),
	)
	if err != nil {
		return fmt.Errorf("update step status: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("%w: step=%s expected=%s", ErrStepTransitionDenied, stepID, expectedStatus)
	}
	return nil
}

// UpdateStepOutput sets the output (cached result) on a step.
func (s *WorkflowStore) UpdateStepOutput(stepID string, output json.RawMessage) error {
	_, err := s.db.Exec(`UPDATE workflow_steps SET output = ? WHERE id = ?`,
		nullableJSON(output), stepID)
	if err != nil {
		return fmt.Errorf("update step output: %w", err)
	}
	return nil
}

// UpdateStepError sets the error message on a step.
func (s *WorkflowStore) UpdateStepError(stepID string, errMsg string) error {
	_, err := s.db.Exec(`UPDATE workflow_steps SET error = ? WHERE id = ?`,
		errMsg, stepID)
	if err != nil {
		return fmt.Errorf("update step error: %w", err)
	}
	return nil
}

// UpdateStepInput sets the input on a step (used when forwarding output from previous step).
func (s *WorkflowStore) UpdateStepInput(stepID string, input json.RawMessage) error {
	_, err := s.db.Exec(`UPDATE workflow_steps SET input = ? WHERE id = ?`,
		nullableJSON(input), stepID)
	if err != nil {
		return fmt.Errorf("update step input: %w", err)
	}
	return nil
}

// GetStepOutput retrieves the cached output for a completed step.
// Returns nil if the step has no output or doesn't exist.
func (s *WorkflowStore) GetStepOutput(workflowID string, stepIndex int) (json.RawMessage, error) {
	var output sql.NullString
	err := s.db.QueryRow(`
		SELECT output FROM workflow_steps
		WHERE workflow_id = ? AND step_index = ? AND status = 'completed'`,
		workflowID, stepIndex).Scan(&output)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get step output: %w", err)
	}
	if !output.Valid || output.String == "" {
		return nil, nil
	}
	return json.RawMessage(output.String), nil
}

// RecordEvent inserts an event into the workflow_events audit log.
func (s *WorkflowStore) RecordEvent(workflowID string, stepIndex *int, eventType EventType, oldState, newState, detail, nodeID string) error {
	_, err := s.db.Exec(`
		INSERT INTO workflow_events (workflow_id, step_index, event_type,
			old_state, new_state, detail, node_id)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		workflowID,
		stepIndex,
		string(eventType),
		nullableString(oldState),
		nullableString(newState),
		nullableString(detail),
		nullableString(nodeID),
	)
	if err != nil {
		return fmt.Errorf("record event: %w", err)
	}
	return nil
}

// GetWorkflowEvents retrieves all events for a workflow, ordered by creation time.
func (s *WorkflowStore) GetWorkflowEvents(workflowID string) ([]WorkflowEvent, error) {
	rows, err := s.db.Query(`
		SELECT id, workflow_id, step_index, event_type, old_state, new_state,
			detail, node_id, created_at
		FROM workflow_events
		WHERE workflow_id = ?
		ORDER BY created_at ASC`, workflowID)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	var events []WorkflowEvent
	for rows.Next() {
		var ev WorkflowEvent
		var stepIndex sql.NullInt64
		var oldState, newState, detail, nodeID sql.NullString
		err := rows.Scan(&ev.ID, &ev.WorkflowID, &stepIndex, &ev.EventType,
			&oldState, &newState, &detail, &nodeID, &ev.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		if stepIndex.Valid {
			idx := int(stepIndex.Int64)
			ev.StepIndex = &idx
		}
		ev.OldState = oldState.String
		ev.NewState = newState.String
		ev.Detail = detail.String
		ev.NodeID = nodeID.String
		events = append(events, ev)
	}
	return events, rows.Err()
}

// LockWorkflow attempts to acquire an exclusive lock on a workflow for processing.
// Uses optimistic locking: only succeeds if the workflow is unlocked or the lock has expired.
// Returns true if the lock was acquired, false if another node holds it.
func (s *WorkflowStore) LockWorkflow(id, nodeID string, duration time.Duration) (bool, error) {
	now := time.Now().UTC()
	until := now.Add(duration)

	res, err := s.db.Exec(`
		UPDATE workflow_runs
		SET locked_by = ?, locked_until = ?, updated_at = ?
		WHERE id = ? AND (locked_until IS NULL OR locked_until < ?)`,
		nodeID, until, now, id, now)
	if err != nil {
		return false, fmt.Errorf("lock workflow: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected: %w", err)
	}
	return affected > 0, nil
}

// UnlockWorkflow releases the lock on a workflow.
func (s *WorkflowStore) UnlockWorkflow(id string) error {
	_, err := s.db.Exec(`
		UPDATE workflow_runs
		SET locked_by = NULL, locked_until = NULL, updated_at = ?
		WHERE id = ?`, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("unlock workflow: %w", err)
	}
	return nil
}

// ReleaseExpiredLocks clears locks where locked_until has passed.
// Used by the reaper goroutine to recover from crashed nodes.
func (s *WorkflowStore) ReleaseExpiredLocks() (int64, error) {
	now := time.Now().UTC()
	res, err := s.db.Exec(`
		UPDATE workflow_runs
		SET locked_by = NULL, locked_until = NULL, updated_at = ?
		WHERE locked_until IS NOT NULL AND locked_until < ?
			AND current_state NOT IN ('completed', 'failed', 'compensated')`,
		now, now)
	if err != nil {
		return 0, fmt.Errorf("release expired locks: %w", err)
	}
	return res.RowsAffected()
}

// --- Scanner helpers ---

func scanWorkflowRun(row *sql.Row) (*WorkflowRun, error) {
	var wf WorkflowRun
	var externalID, input, output, errMsg, metadata, lockedBy sql.NullString
	var lockedUntil sql.NullTime

	err := row.Scan(&wf.ID, &wf.WorkflowType, &wf.Version, &externalID,
		&wf.CurrentState, &wf.CurrentStep,
		&input, &output, &errMsg, &metadata,
		&lockedBy, &lockedUntil,
		&wf.MaxRetries, &wf.RetryCount,
		&wf.CreatedAt, &wf.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrWorkflowNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan workflow: %w", err)
	}

	wf.ExternalID = externalID.String
	if input.Valid {
		wf.Input = json.RawMessage(input.String)
	}
	if output.Valid {
		wf.Output = json.RawMessage(output.String)
	}
	wf.Error = errMsg.String
	if metadata.Valid {
		wf.Metadata = json.RawMessage(metadata.String)
	}
	wf.LockedBy = lockedBy.String
	if lockedUntil.Valid {
		wf.LockedUntil = &lockedUntil.Time
	}
	return &wf, nil
}

func scanWorkflowRunFromRows(rows *sql.Rows) (*WorkflowRun, error) {
	var wf WorkflowRun
	var externalID, input, output, errMsg, metadata, lockedBy sql.NullString
	var lockedUntil sql.NullTime

	err := rows.Scan(&wf.ID, &wf.WorkflowType, &wf.Version, &externalID,
		&wf.CurrentState, &wf.CurrentStep,
		&input, &output, &errMsg, &metadata,
		&lockedBy, &lockedUntil,
		&wf.MaxRetries, &wf.RetryCount,
		&wf.CreatedAt, &wf.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("scan workflow: %w", err)
	}

	wf.ExternalID = externalID.String
	if input.Valid {
		wf.Input = json.RawMessage(input.String)
	}
	if output.Valid {
		wf.Output = json.RawMessage(output.String)
	}
	wf.Error = errMsg.String
	if metadata.Valid {
		wf.Metadata = json.RawMessage(metadata.String)
	}
	wf.LockedBy = lockedBy.String
	if lockedUntil.Valid {
		wf.LockedUntil = &lockedUntil.Time
	}
	return &wf, nil
}

func scanWorkflowStep(rows *sql.Rows) (*WorkflowStep, error) {
	var step WorkflowStep
	var input, output, errMsg, compensateName sql.NullString
	var startedAt, completedAt sql.NullTime

	err := rows.Scan(&step.ID, &step.WorkflowID, &step.StepIndex, &step.StepName,
		&step.ActivityName, &compensateName,
		&step.Status, &input, &output, &errMsg,
		&startedAt, &completedAt)
	if err != nil {
		return nil, fmt.Errorf("scan step: %w", err)
	}

	step.CompensateName = compensateName.String
	if input.Valid {
		step.Input = json.RawMessage(input.String)
	}
	if output.Valid {
		step.Output = json.RawMessage(output.String)
	}
	step.Error = errMsg.String
	if startedAt.Valid {
		step.StartedAt = &startedAt.Time
	}
	if completedAt.Valid {
		step.CompletedAt = &completedAt.Time
	}
	return &step, nil
}

// --- SQL helpers ---

func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func nullableJSON(data json.RawMessage) interface{} {
	if data == nil || len(data) == 0 {
		return nil
	}
	return string(data)
}

func checkRowsAffected(res sql.Result, id string) error {
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("%w: %s", ErrWorkflowNotFound, id)
	}
	return nil
}

// isDuplicateErr checks for SQLite UNIQUE constraint violation errors.
func isDuplicateErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return (len(msg) > 0 &&
		(containsCI(msg, "unique constraint") || containsCI(msg, "UNIQUE constraint")))
}

func containsCI(s, substr string) bool {
	// Simple case-sensitive check — SQLite errors are consistent
	return len(s) >= len(substr) && (s == substr ||
		findSubstring(s, substr))
}

func findSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

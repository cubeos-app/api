package flowengine

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// setupTestDB creates an in-memory SQLite database with FlowEngine tables.
func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}

	// Enable WAL mode and busy timeout like production
	db.Exec("PRAGMA journal_mode=WAL")
	db.Exec("PRAGMA busy_timeout=5000")
	db.Exec("PRAGMA foreign_keys=ON")

	// Create FlowEngine tables (same SQL as migration #16)
	stmts := []string{
		`CREATE TABLE workflow_runs (
			id              TEXT PRIMARY KEY,
			workflow_type   TEXT NOT NULL,
			version         INTEGER NOT NULL DEFAULT 1,
			external_id     TEXT,
			current_state   TEXT NOT NULL DEFAULT 'pending',
			current_step    INTEGER NOT NULL DEFAULT 0,
			input           TEXT,
			output          TEXT,
			error           TEXT,
			metadata        TEXT NOT NULL DEFAULT '{}',
			locked_by       TEXT,
			locked_until    DATETIME,
			max_retries     INTEGER NOT NULL DEFAULT 3,
			retry_count     INTEGER NOT NULL DEFAULT 0,
			created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE UNIQUE INDEX idx_workflow_active_unique
			ON workflow_runs (workflow_type, external_id)
			WHERE current_state NOT IN ('completed', 'failed', 'compensated')`,
		`CREATE INDEX idx_workflow_pending
			ON workflow_runs (current_state, locked_until)
			WHERE current_state IN ('pending', 'running', 'compensating')`,
		`CREATE TABLE workflow_steps (
			id              TEXT PRIMARY KEY,
			workflow_id     TEXT NOT NULL REFERENCES workflow_runs(id) ON DELETE CASCADE,
			step_index      INTEGER NOT NULL,
			step_name       TEXT NOT NULL,
			activity_name   TEXT NOT NULL,
			compensate_name TEXT,
			status          TEXT NOT NULL DEFAULT 'pending',
			input           TEXT,
			output          TEXT,
			error           TEXT,
			started_at      DATETIME,
			completed_at    DATETIME,
			UNIQUE(workflow_id, step_index)
		)`,
		`CREATE TABLE workflow_events (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			workflow_id     TEXT NOT NULL REFERENCES workflow_runs(id) ON DELETE CASCADE,
			step_index      INTEGER,
			event_type      TEXT NOT NULL,
			old_state       TEXT,
			new_state       TEXT,
			detail          TEXT,
			node_id         TEXT,
			created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX idx_workflow_events_workflow
			ON workflow_events (workflow_id, created_at)`,
		`CREATE TABLE job_queue (
			id              TEXT PRIMARY KEY,
			workflow_id     TEXT NOT NULL REFERENCES workflow_runs(id) ON DELETE CASCADE,
			priority        INTEGER NOT NULL DEFAULT 0,
			status          TEXT NOT NULL DEFAULT 'queued',
			created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
	}

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("create table: %v\nSQL: %s", err, stmt)
		}
	}

	t.Cleanup(func() { db.Close() })
	return db
}

func testSteps() []StepDefinition {
	return []StepDefinition{
		{Name: "validate", Action: "app.validate", Compensate: ""},
		{Name: "deploy", Action: "docker.deploy_stack", Compensate: "docker.remove_stack"},
		{Name: "add_dns", Action: "infra.add_dns", Compensate: "infra.remove_dns"},
	}
}

func TestCreateWorkflow(t *testing.T) {
	db := setupTestDB(t)
	store := NewWorkflowStore(db)

	wf, err := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "app_install",
		Version:      1,
		ExternalID:   "my-app",
		Input:        json.RawMessage(`{"name":"my-app"}`),
		Metadata:     json.RawMessage(`{"initiator":"user"}`),
		Steps:        testSteps(),
	})
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}

	if wf.ID == "" {
		t.Fatal("expected non-empty ID")
	}
	if wf.WorkflowType != "app_install" {
		t.Errorf("expected type app_install, got %s", wf.WorkflowType)
	}
	if wf.Version != 1 {
		t.Errorf("expected version 1, got %d", wf.Version)
	}
	if wf.CurrentState != StatePending {
		t.Errorf("expected state pending, got %s", wf.CurrentState)
	}
	if wf.ExternalID != "my-app" {
		t.Errorf("expected external_id my-app, got %s", wf.ExternalID)
	}

	// Verify steps were created
	steps, err := store.GetWorkflowSteps(wf.ID)
	if err != nil {
		t.Fatalf("GetWorkflowSteps: %v", err)
	}
	if len(steps) != 3 {
		t.Fatalf("expected 3 steps, got %d", len(steps))
	}

	// Verify step order and content
	if steps[0].StepName != "validate" || steps[0].ActivityName != "app.validate" {
		t.Errorf("step 0: expected validate/app.validate, got %s/%s", steps[0].StepName, steps[0].ActivityName)
	}
	if steps[1].CompensateName != "docker.remove_stack" {
		t.Errorf("step 1: expected compensate docker.remove_stack, got %s", steps[1].CompensateName)
	}
	if steps[2].StepIndex != 2 {
		t.Errorf("step 2: expected index 2, got %d", steps[2].StepIndex)
	}
}

func TestCreateWorkflow_DefaultValues(t *testing.T) {
	db := setupTestDB(t)
	store := NewWorkflowStore(db)

	wf, err := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "app_remove",
		Steps:        testSteps()[:1],
	})
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}

	if wf.Version != 1 {
		t.Errorf("default version should be 1, got %d", wf.Version)
	}
	if wf.MaxRetries != 3 {
		t.Errorf("default max_retries should be 3, got %d", wf.MaxRetries)
	}
	if string(wf.Metadata) != "{}" {
		t.Errorf("default metadata should be {}, got %s", wf.Metadata)
	}
}

func TestCreateWorkflow_DuplicateActiveBlocked(t *testing.T) {
	db := setupTestDB(t)
	store := NewWorkflowStore(db)

	_, err := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "app_install",
		ExternalID:   "my-app",
		Steps:        testSteps()[:1],
	})
	if err != nil {
		t.Fatalf("first create: %v", err)
	}

	// Second create with same type + external_id should fail
	_, err = store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "app_install",
		ExternalID:   "my-app",
		Steps:        testSteps()[:1],
	})
	if err == nil {
		t.Fatal("expected ErrDuplicateWorkflow")
	}
	if !isErrDuplicateWorkflow(err) {
		t.Fatalf("expected ErrDuplicateWorkflow, got: %v", err)
	}
}

func TestCreateWorkflow_DuplicateAllowedAfterCompletion(t *testing.T) {
	db := setupTestDB(t)
	store := NewWorkflowStore(db)

	wf, err := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "app_install",
		ExternalID:   "my-app",
		Steps:        testSteps()[:1],
	})
	if err != nil {
		t.Fatalf("first create: %v", err)
	}

	// Complete the workflow
	if err := store.UpdateWorkflowState(wf.ID, StateCompleted, 0); err != nil {
		t.Fatalf("update state: %v", err)
	}

	// Now a new workflow with the same type + external_id should work
	wf2, err := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "app_install",
		ExternalID:   "my-app",
		Steps:        testSteps()[:1],
	})
	if err != nil {
		t.Fatalf("second create after completion: %v", err)
	}
	if wf2.ID == wf.ID {
		t.Error("expected different workflow IDs")
	}
}

func TestGetWorkflow(t *testing.T) {
	db := setupTestDB(t)
	store := NewWorkflowStore(db)

	wf, _ := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "app_install",
		ExternalID:   "test-app",
		Input:        json.RawMessage(`{"key":"value"}`),
		Steps:        testSteps(),
	})

	got, err := store.GetWorkflow(wf.ID)
	if err != nil {
		t.Fatalf("GetWorkflow: %v", err)
	}

	if got.ID != wf.ID {
		t.Errorf("ID mismatch: %s vs %s", got.ID, wf.ID)
	}
	if got.WorkflowType != "app_install" {
		t.Errorf("type: expected app_install, got %s", got.WorkflowType)
	}
	if string(got.Input) != `{"key":"value"}` {
		t.Errorf("input: expected {\"key\":\"value\"}, got %s", got.Input)
	}
}

func TestGetWorkflow_NotFound(t *testing.T) {
	db := setupTestDB(t)
	store := NewWorkflowStore(db)

	_, err := store.GetWorkflow("nonexistent-id")
	if err != ErrWorkflowNotFound {
		t.Fatalf("expected ErrWorkflowNotFound, got: %v", err)
	}
}

func TestGetWorkflowByExternalID(t *testing.T) {
	db := setupTestDB(t)
	store := NewWorkflowStore(db)

	wf, _ := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "app_install",
		ExternalID:   "my-app",
		Steps:        testSteps()[:1],
	})

	got, err := store.GetWorkflowByExternalID("app_install", "my-app")
	if err != nil {
		t.Fatalf("GetWorkflowByExternalID: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if got.ID != wf.ID {
		t.Errorf("ID mismatch")
	}

	// Non-existent should return nil, not error
	got2, err := store.GetWorkflowByExternalID("app_install", "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got2 != nil {
		t.Fatal("expected nil for nonexistent external_id")
	}
}

func TestUpdateWorkflowState(t *testing.T) {
	db := setupTestDB(t)
	store := NewWorkflowStore(db)

	wf, _ := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "app_install",
		Steps:        testSteps(),
	})

	if err := store.UpdateWorkflowState(wf.ID, StateRunning, 1); err != nil {
		t.Fatalf("UpdateWorkflowState: %v", err)
	}

	got, _ := store.GetWorkflow(wf.ID)
	if got.CurrentState != StateRunning {
		t.Errorf("expected running, got %s", got.CurrentState)
	}
	if got.CurrentStep != 1 {
		t.Errorf("expected step 1, got %d", got.CurrentStep)
	}
}

func TestUpdateWorkflowState_NotFound(t *testing.T) {
	db := setupTestDB(t)
	store := NewWorkflowStore(db)

	err := store.UpdateWorkflowState("nonexistent", StateRunning, 0)
	if err == nil {
		t.Fatal("expected error for nonexistent workflow")
	}
}

func TestUpdateStepStatus_Atomic(t *testing.T) {
	db := setupTestDB(t)
	store := NewWorkflowStore(db)

	wf, _ := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "app_install",
		Steps:        testSteps(),
	})

	steps, _ := store.GetWorkflowSteps(wf.ID)

	// pending → running should succeed
	if err := store.UpdateStepStatus(steps[0].ID, StepPending, StepRunning); err != nil {
		t.Fatalf("pending→running: %v", err)
	}

	// running → completed should succeed
	if err := store.UpdateStepStatus(steps[0].ID, StepRunning, StepCompleted); err != nil {
		t.Fatalf("running→completed: %v", err)
	}

	// pending → completed should fail (current status is completed, not pending)
	err := store.UpdateStepStatus(steps[0].ID, StepPending, StepCompleted)
	if err == nil {
		t.Fatal("expected ErrStepTransitionDenied")
	}
	if !IsStepTransitionDenied(err) {
		t.Fatalf("expected step transition denied, got: %v", err)
	}
}

func TestUpdateStepOutput_And_GetStepOutput(t *testing.T) {
	db := setupTestDB(t)
	store := NewWorkflowStore(db)

	wf, _ := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "app_install",
		Steps:        testSteps(),
	})
	steps, _ := store.GetWorkflowSteps(wf.ID)

	// Set output and mark completed
	output := json.RawMessage(`{"stack_id":"abc123"}`)
	if err := store.UpdateStepOutput(steps[0].ID, output); err != nil {
		t.Fatalf("UpdateStepOutput: %v", err)
	}
	store.UpdateStepStatus(steps[0].ID, StepPending, StepRunning)
	store.UpdateStepStatus(steps[0].ID, StepRunning, StepCompleted)

	// Retrieve cached output
	got, err := store.GetStepOutput(wf.ID, 0)
	if err != nil {
		t.Fatalf("GetStepOutput: %v", err)
	}
	if string(got) != `{"stack_id":"abc123"}` {
		t.Errorf("expected abc123 output, got %s", got)
	}

	// Non-completed step should return nil
	got2, err := store.GetStepOutput(wf.ID, 1)
	if err != nil {
		t.Fatalf("GetStepOutput for pending step: %v", err)
	}
	if got2 != nil {
		t.Errorf("expected nil for pending step, got %s", got2)
	}
}

func TestGetIncompleteWorkflows(t *testing.T) {
	db := setupTestDB(t)
	store := NewWorkflowStore(db)

	// Create 3 workflows in different states
	wf1, _ := store.CreateWorkflow(CreateWorkflowParams{WorkflowType: "a", Steps: testSteps()[:1]})
	wf2, _ := store.CreateWorkflow(CreateWorkflowParams{WorkflowType: "b", ExternalID: "b1", Steps: testSteps()[:1]})
	wf3, _ := store.CreateWorkflow(CreateWorkflowParams{WorkflowType: "c", ExternalID: "c1", Steps: testSteps()[:1]})

	// Complete wf2
	store.UpdateWorkflowState(wf2.ID, StateCompleted, 0)

	// wf1 (pending) and wf3 (pending) should be returned
	_ = wf1
	_ = wf3
	incomplete, err := store.GetIncompleteWorkflows()
	if err != nil {
		t.Fatalf("GetIncompleteWorkflows: %v", err)
	}
	if len(incomplete) != 2 {
		t.Fatalf("expected 2 incomplete, got %d", len(incomplete))
	}
}

func TestRecordEvent_And_GetEvents(t *testing.T) {
	db := setupTestDB(t)
	store := NewWorkflowStore(db)

	wf, _ := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "app_install",
		Steps:        testSteps(),
	})

	stepIdx := 0
	if err := store.RecordEvent(wf.ID, &stepIdx, EventStateChange, "pending", "running", "", "node-1"); err != nil {
		t.Fatalf("RecordEvent: %v", err)
	}
	if err := store.RecordEvent(wf.ID, &stepIdx, EventRetry, "", "", "attempt 2/3", "node-1"); err != nil {
		t.Fatalf("RecordEvent retry: %v", err)
	}

	events, err := store.GetWorkflowEvents(wf.ID)
	if err != nil {
		t.Fatalf("GetWorkflowEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].EventType != EventStateChange {
		t.Errorf("expected state_change, got %s", events[0].EventType)
	}
	if events[0].NodeID != "node-1" {
		t.Errorf("expected node-1, got %s", events[0].NodeID)
	}
	if events[1].Detail != "attempt 2/3" {
		t.Errorf("expected retry detail, got %s", events[1].Detail)
	}
}

func TestLockWorkflow(t *testing.T) {
	db := setupTestDB(t)
	store := NewWorkflowStore(db)

	wf, _ := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "app_install",
		Steps:        testSteps()[:1],
	})

	// First lock should succeed
	locked, err := store.LockWorkflow(wf.ID, "node-1", 30*time.Second)
	if err != nil {
		t.Fatalf("LockWorkflow: %v", err)
	}
	if !locked {
		t.Fatal("expected lock acquired")
	}

	// Second lock by different node should fail (lock not expired)
	locked2, err := store.LockWorkflow(wf.ID, "node-2", 30*time.Second)
	if err != nil {
		t.Fatalf("LockWorkflow 2: %v", err)
	}
	if locked2 {
		t.Fatal("expected lock NOT acquired (already locked)")
	}

	// Unlock should allow re-locking
	if err := store.UnlockWorkflow(wf.ID); err != nil {
		t.Fatalf("UnlockWorkflow: %v", err)
	}

	locked3, err := store.LockWorkflow(wf.ID, "node-2", 30*time.Second)
	if err != nil {
		t.Fatalf("LockWorkflow 3: %v", err)
	}
	if !locked3 {
		t.Fatal("expected lock acquired after unlock")
	}
}

func TestReleaseExpiredLocks(t *testing.T) {
	db := setupTestDB(t)
	store := NewWorkflowStore(db)

	wf, _ := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "app_install",
		Steps:        testSteps()[:1],
	})

	// Lock with zero duration (immediately expired)
	store.LockWorkflow(wf.ID, "node-1", 0)

	// Small delay to ensure expiry
	time.Sleep(10 * time.Millisecond)

	released, err := store.ReleaseExpiredLocks()
	if err != nil {
		t.Fatalf("ReleaseExpiredLocks: %v", err)
	}
	if released != 1 {
		t.Fatalf("expected 1 released, got %d", released)
	}

	// Verify workflow is now unlockable
	got, _ := store.GetWorkflow(wf.ID)
	if got.LockedBy != "" {
		t.Errorf("expected empty locked_by, got %s", got.LockedBy)
	}
}

func TestUpdateWorkflowOutput(t *testing.T) {
	db := setupTestDB(t)
	store := NewWorkflowStore(db)

	wf, _ := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "app_install",
		Steps:        testSteps()[:1],
	})

	output := json.RawMessage(`{"result":"success","app":"my-app"}`)
	if err := store.UpdateWorkflowOutput(wf.ID, StateCompleted, output); err != nil {
		t.Fatalf("UpdateWorkflowOutput: %v", err)
	}

	got, _ := store.GetWorkflow(wf.ID)
	if got.CurrentState != StateCompleted {
		t.Errorf("expected completed, got %s", got.CurrentState)
	}
	if string(got.Output) != string(output) {
		t.Errorf("output mismatch: %s", got.Output)
	}
}

func TestUpdateWorkflowError(t *testing.T) {
	db := setupTestDB(t)
	store := NewWorkflowStore(db)

	wf, _ := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "app_install",
		Steps:        testSteps()[:1],
	})

	if err := store.UpdateWorkflowError(wf.ID, StateFailed, "deploy failed: timeout"); err != nil {
		t.Fatalf("UpdateWorkflowError: %v", err)
	}

	got, _ := store.GetWorkflow(wf.ID)
	if got.CurrentState != StateFailed {
		t.Errorf("expected failed, got %s", got.CurrentState)
	}
	if got.Error != "deploy failed: timeout" {
		t.Errorf("error mismatch: %s", got.Error)
	}
}

func TestNewUUID_Uniqueness(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		id := newUUID()
		if seen[id] {
			t.Fatalf("duplicate UUID at iteration %d: %s", i, id)
		}
		seen[id] = true

		// Basic format check: 8-4-4-4-12
		if len(id) != 36 {
			t.Fatalf("unexpected UUID length %d: %s", len(id), id)
		}
		if id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
			t.Fatalf("unexpected UUID format: %s", id)
		}
	}
}

// Helper to check for ErrDuplicateWorkflow wrapped errors
func isErrDuplicateWorkflow(err error) bool {
	if err == nil {
		return false
	}
	return findSubstring(err.Error(), "duplicate active workflow")
}

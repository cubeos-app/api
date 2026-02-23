package flowengine

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// testDB creates an in-memory SQLite database with FlowEngine tables.
func testDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	// Enable WAL + foreign keys
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.Exec(pragma); err != nil {
			t.Fatal(err)
		}
	}
	// Create tables
	createSQL := `
	CREATE TABLE IF NOT EXISTS workflow_runs (
		id TEXT PRIMARY KEY,
		workflow_type TEXT NOT NULL,
		version INTEGER DEFAULT 1,
		external_id TEXT,
		current_state TEXT DEFAULT 'pending',
		current_step INTEGER DEFAULT 0,
		input TEXT,
		output TEXT,
		error TEXT,
		metadata TEXT DEFAULT '{}',
		locked_by TEXT,
		locked_until DATETIME,
		max_retries INTEGER DEFAULT 3,
		retry_count INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT (datetime('now')),
		updated_at DATETIME DEFAULT (datetime('now'))
	);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_workflow_active_unique 
		ON workflow_runs(workflow_type, external_id)
		WHERE current_state NOT IN ('completed','failed','compensated');
	CREATE INDEX IF NOT EXISTS idx_workflow_pending
		ON workflow_runs(current_state, locked_until)
		WHERE current_state IN ('pending','running','compensating');
	CREATE TABLE IF NOT EXISTS workflow_steps (
		id TEXT PRIMARY KEY,
		workflow_id TEXT NOT NULL REFERENCES workflow_runs(id) ON DELETE CASCADE,
		step_index INTEGER NOT NULL,
		step_name TEXT NOT NULL,
		activity_name TEXT NOT NULL DEFAULT '',
		compensate_name TEXT DEFAULT '',
		status TEXT DEFAULT 'pending',
		input TEXT,
		output TEXT,
		error TEXT,
		started_at DATETIME,
		completed_at DATETIME,
		UNIQUE(workflow_id, step_index)
	);
	CREATE TABLE IF NOT EXISTS workflow_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		workflow_id TEXT NOT NULL,
		step_index INTEGER,
		event_type TEXT NOT NULL,
		old_state TEXT,
		new_state TEXT,
		detail TEXT,
		node_id TEXT,
		created_at DATETIME DEFAULT (datetime('now'))
	);
	CREATE TABLE IF NOT EXISTS job_queue (
		id TEXT PRIMARY KEY,
		workflow_id TEXT REFERENCES workflow_runs(id),
		priority INTEGER DEFAULT 0,
		status TEXT DEFAULT 'queued',
		created_at DATETIME DEFAULT (datetime('now'))
	);
	`
	if _, err := db.Exec(createSQL); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// testRegistry creates a registry with mock activities for testing.
// failAtStep, if >= 0, causes that step's activity to return an error.
// compensateFailAt, if >= 0, causes that step's compensation to fail.
func testRegistry(failAtStep, compensateFailAt int) *ActivityRegistry {
	reg := NewActivityRegistry()

	for i := 0; i < 5; i++ {
		stepNum := i
		reg.MustRegister(fmt.Sprintf("step_%d", stepNum), func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
			if stepNum == failAtStep {
				return nil, NewPermanentError(fmt.Errorf("step_%d forced failure", stepNum))
			}
			out := fmt.Sprintf(`{"step":%d,"status":"done"}`, stepNum)
			return json.RawMessage(out), nil
		})
		reg.MustRegister(fmt.Sprintf("compensate_%d", stepNum), func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
			if stepNum == compensateFailAt {
				return nil, NewPermanentError(fmt.Errorf("compensate_%d forced failure", stepNum))
			}
			return json.RawMessage(`{"compensated":true}`), nil
		})
	}

	return reg
}

// testWorkflowDef creates a 5-step test workflow definition.
type testWorkflowDef struct {
	steps []StepDefinition
}

func (d testWorkflowDef) Type() string { return "test_workflow" }
func (d testWorkflowDef) Version() int { return 1 }
func (d testWorkflowDef) Steps() []StepDefinition {
	if d.steps != nil {
		return d.steps
	}
	steps := make([]StepDefinition, 5)
	for i := 0; i < 5; i++ {
		steps[i] = StepDefinition{
			Name:       fmt.Sprintf("step_%d", i),
			Action:     fmt.Sprintf("step_%d", i),
			Compensate: fmt.Sprintf("compensate_%d", i),
			Retry: &RetryPolicy{
				MaxAttempts:     1, // No retries in tests
				InitialInterval: 0,
				MaxInterval:     0,
			},
			Timeout: 5 * time.Second,
		}
	}
	return steps
}

func TestSagaHappyPath(t *testing.T) {
	db := testDB(t)
	store := NewWorkflowStore(db)
	reg := testRegistry(-1, -1) // no failures
	executor := NewStepExecutor(store, reg)
	saga := NewSagaOrchestrator(store, executor, reg, "test-node")

	// Create workflow
	wf, err := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "test_workflow",
		Version:      1,
		ExternalID:   "test-1",
		Input:        json.RawMessage(`{"action":"test"}`),
		Steps:        testWorkflowDef{}.Steps(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Execute
	err = saga.Execute(context.Background(), wf)
	if err != nil {
		t.Fatalf("Expected success, got: %v", err)
	}

	// Verify final state
	result, err := store.GetWorkflow(wf.ID)
	if err != nil {
		t.Fatal(err)
	}
	if result.CurrentState != StateCompleted {
		t.Errorf("Expected state=completed, got %s", result.CurrentState)
	}

	// Verify all steps completed
	steps, _ := store.GetWorkflowSteps(wf.ID)
	for _, step := range steps {
		if step.Status != StepCompleted {
			t.Errorf("Step %d (%s): expected completed, got %s", step.StepIndex, step.StepName, step.Status)
		}
	}

	// Verify events were recorded
	events, _ := store.GetWorkflowEvents(wf.ID)
	if len(events) == 0 {
		t.Error("Expected workflow events to be recorded")
	}
}

func TestSagaFailureAtStep0_NoCompensation(t *testing.T) {
	db := testDB(t)
	store := NewWorkflowStore(db)
	reg := testRegistry(0, -1) // fail at step 0
	executor := NewStepExecutor(store, reg)
	saga := NewSagaOrchestrator(store, executor, reg, "test-node")

	wf, _ := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "test_workflow",
		Version:      1,
		ExternalID:   "fail-0",
		Input:        json.RawMessage(`{}`),
		Steps:        testWorkflowDef{}.Steps(),
	})

	err := saga.Execute(context.Background(), wf)
	// Compensation should succeed (no steps to compensate since step 0 failed)
	if err != nil {
		t.Fatalf("Expected nil (compensated with no steps), got: %v", err)
	}

	result, _ := store.GetWorkflow(wf.ID)
	// No completed steps to compensate → compensated state
	if result.CurrentState != StateCompensated {
		t.Errorf("Expected state=compensated, got %s", result.CurrentState)
	}
}

func TestSagaFailureAtStep2_CompensatesSteps0And1(t *testing.T) {
	db := testDB(t)
	store := NewWorkflowStore(db)
	reg := testRegistry(2, -1) // fail at step 2
	executor := NewStepExecutor(store, reg)
	saga := NewSagaOrchestrator(store, executor, reg, "test-node")

	wf, _ := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "test_workflow",
		Version:      1,
		ExternalID:   "fail-2",
		Input:        json.RawMessage(`{}`),
		Steps:        testWorkflowDef{}.Steps(),
	})

	err := saga.Execute(context.Background(), wf)
	if err != nil {
		t.Fatalf("Expected nil (all compensations succeeded), got: %v", err)
	}

	result, _ := store.GetWorkflow(wf.ID)
	if result.CurrentState != StateCompensated {
		t.Errorf("Expected state=compensated, got %s", result.CurrentState)
	}

	// Verify step states
	steps, _ := store.GetWorkflowSteps(wf.ID)
	// Steps 0,1 should be compensated
	for i := 0; i < 2; i++ {
		if steps[i].Status != StepCompensated {
			t.Errorf("Step %d: expected compensated, got %s", i, steps[i].Status)
		}
	}
	// Step 2 should be failed
	if steps[2].Status != StepFailed {
		t.Errorf("Step 2: expected failed, got %s", steps[2].Status)
	}
	// Steps 3,4 should be pending (never executed)
	for i := 3; i < 5; i++ {
		if steps[i].Status != StepPending {
			t.Errorf("Step %d: expected pending, got %s", i, steps[i].Status)
		}
	}
}

func TestSagaFailureAtStep4_CompensatesAll(t *testing.T) {
	db := testDB(t)
	store := NewWorkflowStore(db)
	reg := testRegistry(4, -1) // fail at last step
	executor := NewStepExecutor(store, reg)
	saga := NewSagaOrchestrator(store, executor, reg, "test-node")

	wf, _ := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "test_workflow",
		Version:      1,
		ExternalID:   "fail-4",
		Input:        json.RawMessage(`{}`),
		Steps:        testWorkflowDef{}.Steps(),
	})

	err := saga.Execute(context.Background(), wf)
	if err != nil {
		t.Fatalf("Expected nil (all compensations succeeded), got: %v", err)
	}

	result, _ := store.GetWorkflow(wf.ID)
	if result.CurrentState != StateCompensated {
		t.Errorf("Expected state=compensated, got %s", result.CurrentState)
	}

	// Steps 0-3 should be compensated, step 4 failed
	steps, _ := store.GetWorkflowSteps(wf.ID)
	for i := 0; i < 4; i++ {
		if steps[i].Status != StepCompensated {
			t.Errorf("Step %d: expected compensated, got %s", i, steps[i].Status)
		}
	}
	if steps[4].Status != StepFailed {
		t.Errorf("Step 4: expected failed, got %s", steps[4].Status)
	}
}

func TestSagaCompensationFailure(t *testing.T) {
	db := testDB(t)
	store := NewWorkflowStore(db)
	reg := testRegistry(3, 1) // fail at step 3, compensation of step 1 also fails
	executor := NewStepExecutor(store, reg)
	saga := NewSagaOrchestrator(store, executor, reg, "test-node")

	wf, _ := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "test_workflow",
		Version:      1,
		ExternalID:   "comp-fail",
		Input:        json.RawMessage(`{}`),
		Steps:        testWorkflowDef{}.Steps(),
	})

	err := saga.Execute(context.Background(), wf)
	if err == nil {
		t.Fatal("Expected error from failed compensation")
	}

	result, _ := store.GetWorkflow(wf.ID)
	if result.CurrentState != StateFailed {
		t.Errorf("Expected state=failed (compensation failed), got %s", result.CurrentState)
	}
	if !strings.Contains(result.Error, "compensation") {
		t.Errorf("Expected error to mention compensation, got: %s", result.Error)
	}
}

func TestSagaNoSteps(t *testing.T) {
	db := testDB(t)
	store := NewWorkflowStore(db)
	reg := NewActivityRegistry()
	executor := NewStepExecutor(store, reg)
	saga := NewSagaOrchestrator(store, executor, reg, "test-node")

	// Create workflow with no steps
	wf, err := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "empty_workflow",
		Version:      1,
		ExternalID:   "empty",
		Input:        json.RawMessage(`{}`),
		Steps:        nil,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = saga.Execute(context.Background(), wf)
	if err != nil {
		t.Fatalf("Expected success for empty workflow, got: %v", err)
	}

	result, _ := store.GetWorkflow(wf.ID)
	if result.CurrentState != StateCompleted {
		t.Errorf("Expected state=completed, got %s", result.CurrentState)
	}
}

func TestSagaStepWithNoCompensation(t *testing.T) {
	db := testDB(t)
	store := NewWorkflowStore(db)
	reg := NewActivityRegistry()

	// Register activities: step_0 succeeds, step_1 fails, step_0 has no compensation
	reg.MustRegister("step_0", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{"done":true}`), nil
	})
	reg.MustRegister("step_1", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return nil, NewPermanentError(fmt.Errorf("forced failure"))
	})

	executor := NewStepExecutor(store, reg)
	saga := NewSagaOrchestrator(store, executor, reg, "test-node")

	steps := []StepDefinition{
		{Name: "step_0", Action: "step_0", Compensate: ""}, // No compensation
		{Name: "step_1", Action: "step_1", Compensate: ""},
	}

	wf, _ := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "no_comp",
		Version:      1,
		ExternalID:   "no-comp-1",
		Input:        json.RawMessage(`{}`),
		Steps:        steps,
	})

	err := saga.Execute(context.Background(), wf)
	if err != nil {
		t.Fatalf("Expected nil (compensation skipped for steps without compensate), got: %v", err)
	}

	result, _ := store.GetWorkflow(wf.ID)
	if result.CurrentState != StateCompensated {
		t.Errorf("Expected state=compensated, got %s", result.CurrentState)
	}
}

func TestSagaContextCancellation(t *testing.T) {
	db := testDB(t)
	store := NewWorkflowStore(db)
	reg := NewActivityRegistry()

	// Register a slow activity
	reg.MustRegister("slow", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
			return json.RawMessage(`{}`), nil
		}
	})

	executor := NewStepExecutor(store, reg)
	saga := NewSagaOrchestrator(store, executor, reg, "test-node")

	steps := []StepDefinition{
		{Name: "slow_step", Action: "slow", Timeout: 5 * time.Second},
	}
	wf, _ := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "slow_wf",
		Version:      1,
		ExternalID:   "slow-1",
		Input:        json.RawMessage(`{}`),
		Steps:        steps,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := saga.Execute(ctx, wf)
	// Step 0 fails from deadline, no completed steps to compensate,
	// so compensation succeeds (nothing to undo) and returns nil.
	// Verify the workflow recorded the error and ended in compensated state.
	if err != nil {
		t.Logf("Got error (acceptable): %v", err)
	}

	result, _ := store.GetWorkflow(wf.ID)
	if result.CurrentState != StateCompensated && result.CurrentState != StateFailed {
		t.Errorf("Expected compensated or failed state, got %s", result.CurrentState)
	}
	if result.Error == "" {
		t.Error("Expected workflow error to be recorded")
	}
}

func TestSagaResumeFromCompensating(t *testing.T) {
	db := testDB(t)
	store := NewWorkflowStore(db)
	reg := NewActivityRegistry()

	// Register activities
	reg.MustRegister("ok_step", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{"ok":true}`), nil
	})
	reg.MustRegister("compensate_ok", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{"compensated":true}`), nil
	})

	executor := NewStepExecutor(store, reg)
	saga := NewSagaOrchestrator(store, executor, reg, "test-node")

	steps := []StepDefinition{
		{Name: "step_0", Action: "ok_step", Compensate: "compensate_ok"},
		{Name: "step_1", Action: "ok_step", Compensate: "compensate_ok"},
	}
	wf, _ := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "resume_comp",
		Version:      1,
		ExternalID:   "resume-1",
		Input:        json.RawMessage(`{}`),
		Steps:        steps,
	})

	// Simulate crash during compensation: workflow in compensating state,
	// step 0 completed, step 1 failed
	_ = store.UpdateWorkflowState(wf.ID, StateRunning, 0)
	allSteps, _ := store.GetWorkflowSteps(wf.ID)
	_ = store.UpdateStepStatus(allSteps[0].ID, StepPending, StepRunning)
	_ = store.UpdateStepStatus(allSteps[0].ID, StepRunning, StepCompleted)
	_ = store.UpdateStepStatus(allSteps[1].ID, StepPending, StepRunning)
	_ = store.UpdateStepStatus(allSteps[1].ID, StepRunning, StepFailed)
	_ = store.UpdateWorkflowState(wf.ID, StateCompensating, 1)

	// Re-fetch the workflow in its crashed state
	wf, _ = store.GetWorkflow(wf.ID)

	// Execute should resume compensation
	err := saga.Execute(context.Background(), wf)
	if err != nil {
		t.Fatalf("Expected successful compensation resume, got: %v", err)
	}

	result, _ := store.GetWorkflow(wf.ID)
	if result.CurrentState != StateCompensated {
		t.Errorf("Expected state=compensated, got %s", result.CurrentState)
	}
}

func TestSagaIdempotentStepSkip(t *testing.T) {
	db := testDB(t)
	store := NewWorkflowStore(db)
	reg := NewActivityRegistry()

	callCount := 0
	reg.MustRegister("counting", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		callCount++
		return json.RawMessage(`{"count":1}`), nil
	})

	executor := NewStepExecutor(store, reg)
	saga := NewSagaOrchestrator(store, executor, reg, "test-node")

	steps := []StepDefinition{
		{Name: "count_step", Action: "counting"},
		{Name: "count_step_2", Action: "counting"},
	}
	wf, _ := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "idempotent",
		Version:      1,
		ExternalID:   "idemp-1",
		Input:        json.RawMessage(`{}`),
		Steps:        steps,
	})

	// Pre-complete step 0
	allSteps, _ := store.GetWorkflowSteps(wf.ID)
	_ = store.UpdateStepStatus(allSteps[0].ID, StepPending, StepRunning)
	_ = store.UpdateStepStatus(allSteps[0].ID, StepRunning, StepCompleted)
	_ = store.UpdateStepOutput(allSteps[0].ID, json.RawMessage(`{"cached":"yes"}`))

	err := saga.Execute(context.Background(), wf)
	if err != nil {
		t.Fatalf("Expected success, got: %v", err)
	}

	// Only step 1 should have been executed (step 0 was already completed)
	if callCount != 1 {
		t.Errorf("Expected 1 activity call (step 0 skipped), got %d", callCount)
	}
}

func TestSagaOutputPipeline(t *testing.T) {
	db := testDB(t)
	store := NewWorkflowStore(db)
	reg := NewActivityRegistry()

	// Step 0 outputs data, step 1 receives it as input
	var step1Input json.RawMessage
	reg.MustRegister("producer", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{"message":"hello from step 0"}`), nil
	})
	reg.MustRegister("consumer", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		step1Input = input
		return json.RawMessage(`{"received":true}`), nil
	})

	executor := NewStepExecutor(store, reg)
	saga := NewSagaOrchestrator(store, executor, reg, "test-node")

	steps := []StepDefinition{
		{Name: "produce", Action: "producer"},
		{Name: "consume", Action: "consumer"},
	}
	wf, _ := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "pipeline",
		Version:      1,
		ExternalID:   "pipe-1",
		Input:        json.RawMessage(`{"initial":"data"}`),
		Steps:        steps,
	})

	err := saga.Execute(context.Background(), wf)
	if err != nil {
		t.Fatalf("Expected success, got: %v", err)
	}

	// Step 1 should have received step 0's output as input
	if step1Input == nil {
		t.Fatal("Step 1 did not receive input")
	}
	if !strings.Contains(string(step1Input), "hello from step 0") {
		t.Errorf("Step 1 received unexpected input: %s", string(step1Input))
	}
}

func TestSagaExecuteWithTimeout(t *testing.T) {
	db := testDB(t)
	store := NewWorkflowStore(db)
	reg := NewActivityRegistry()

	reg.MustRegister("fast", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{}`), nil
	})

	executor := NewStepExecutor(store, reg)
	saga := NewSagaOrchestrator(store, executor, reg, "test-node")

	steps := []StepDefinition{{Name: "fast_step", Action: "fast"}}
	wf, _ := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "timeout_wf",
		Version:      1,
		ExternalID:   "to-1",
		Input:        json.RawMessage(`{}`),
		Steps:        steps,
	})

	err := saga.ExecuteWithTimeout(context.Background(), wf, 5*time.Second)
	if err != nil {
		t.Fatalf("Expected success with generous timeout, got: %v", err)
	}

	result, _ := store.GetWorkflow(wf.ID)
	if result.CurrentState != StateCompleted {
		t.Errorf("Expected completed, got %s", result.CurrentState)
	}
}

// --- Fat Envelope (mergeJSON) Tests ---

func TestMergeJSONBasic(t *testing.T) {
	dst := json.RawMessage(`{"a":1}`)
	src := json.RawMessage(`{"b":2}`)
	result := mergeJSON(dst, src)

	var m map[string]json.RawMessage
	if err := json.Unmarshal(result, &m); err != nil {
		t.Fatalf("mergeJSON result is not valid JSON: %v", err)
	}
	if _, ok := m["a"]; !ok {
		t.Error("expected key 'a' in merged result")
	}
	if _, ok := m["b"]; !ok {
		t.Error("expected key 'b' in merged result")
	}
}

func TestMergeJSONSrcOverridesDst(t *testing.T) {
	dst := json.RawMessage(`{"key":"original","other":"kept"}`)
	src := json.RawMessage(`{"key":"override"}`)
	result := mergeJSON(dst, src)

	var m map[string]interface{}
	json.Unmarshal(result, &m)
	if m["key"] != "override" {
		t.Errorf("expected src key to override dst, got: %v", m["key"])
	}
	if m["other"] != "kept" {
		t.Errorf("expected non-overridden key to be kept, got: %v", m["other"])
	}
}

func TestMergeJSONEmptySrc(t *testing.T) {
	dst := json.RawMessage(`{"a":1}`)
	result := mergeJSON(dst, nil)
	if string(result) != string(dst) {
		t.Errorf("expected dst unchanged when src is nil, got: %s", result)
	}
}

func TestMergeJSONEmptyDst(t *testing.T) {
	src := json.RawMessage(`{"b":2}`)
	result := mergeJSON(nil, src)
	if string(result) != string(src) {
		t.Errorf("expected src returned when dst is nil, got: %s", result)
	}
}

func TestMergeJSONNonObjectSrc(t *testing.T) {
	// Non-object src should return dst unchanged
	dst := json.RawMessage(`{"a":1}`)
	src := json.RawMessage(`"not an object"`)
	result := mergeJSON(dst, src)
	if string(result) != string(dst) {
		t.Errorf("expected dst unchanged for non-object src, got: %s", result)
	}
}

// TestSagaFatEnvelopeWorkflowInput verifies that step 1 receives workflow.Input merged
// with step 0's output (not just step 0's output alone).
func TestSagaFatEnvelopeWorkflowInput(t *testing.T) {
	db := testDB(t)
	store := NewWorkflowStore(db)
	reg := NewActivityRegistry()

	var step1Input json.RawMessage
	reg.MustRegister("step_a", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{"from_step_a":"yes"}`), nil
	})
	reg.MustRegister("step_b", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		step1Input = input
		return json.RawMessage(`{"done":true}`), nil
	})

	executor := NewStepExecutor(store, reg)
	saga := NewSagaOrchestrator(store, executor, reg, "test-node")

	steps := []StepDefinition{
		{Name: "a", Action: "step_a"},
		{Name: "b", Action: "step_b"},
	}
	wf, _ := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "envelope_wf",
		Version:      1,
		ExternalID:   "env-1",
		Input:        json.RawMessage(`{"workflow_param":"initial"}`),
		Steps:        steps,
	})

	err := saga.Execute(context.Background(), wf)
	if err != nil {
		t.Fatalf("Expected success, got: %v", err)
	}

	// step_b should see BOTH workflow.Input AND step_a's output
	if step1Input == nil {
		t.Fatal("Step b did not receive input")
	}
	if !strings.Contains(string(step1Input), "workflow_param") {
		t.Errorf("Step b missing workflow.Input data; got: %s", string(step1Input))
	}
	if !strings.Contains(string(step1Input), "from_step_a") {
		t.Errorf("Step b missing step_a output data; got: %s", string(step1Input))
	}
}

// TestSagaFatEnvelopeStepSeesPriorSteps verifies that step 2 sees data from both
// step 0 and step 1 (not just the immediately preceding step).
func TestSagaFatEnvelopeStepSeesPriorSteps(t *testing.T) {
	db := testDB(t)
	store := NewWorkflowStore(db)
	reg := NewActivityRegistry()

	var step2Input json.RawMessage
	reg.MustRegister("step_0", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{"port":6100}`), nil
	})
	reg.MustRegister("step_1", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{"domain":"app.cubeos.cube"}`), nil
	})
	reg.MustRegister("step_2", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		step2Input = input
		return json.RawMessage(`{"done":true}`), nil
	})

	executor := NewStepExecutor(store, reg)
	saga := NewSagaOrchestrator(store, executor, reg, "test-node")

	steps := []StepDefinition{
		{Name: "alloc_port", Action: "step_0"},
		{Name: "add_dns", Action: "step_1"},
		{Name: "create_proxy", Action: "step_2"},
	}
	wf, _ := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "multi_step_envelope",
		Version:      1,
		ExternalID:   "env-2",
		Input:        json.RawMessage(`{"app_name":"myapp"}`),
		Steps:        steps,
	})

	err := saga.Execute(context.Background(), wf)
	if err != nil {
		t.Fatalf("Expected success, got: %v", err)
	}

	// step_2 should see app_name (workflow input), port (step 0), and domain (step 1)
	if step2Input == nil {
		t.Fatal("step_2 did not receive input")
	}
	if !strings.Contains(string(step2Input), "app_name") {
		t.Errorf("step_2 missing workflow input field; got: %s", string(step2Input))
	}
	if !strings.Contains(string(step2Input), "port") {
		t.Errorf("step_2 missing step_0 output; got: %s", string(step2Input))
	}
	if !strings.Contains(string(step2Input), "domain") {
		t.Errorf("step_2 missing step_1 output; got: %s", string(step2Input))
	}
}

// TestSagaFatEnvelopeRecovery verifies that after crash recovery, the re-executed
// step still sees all prior step data in the envelope.
func TestSagaFatEnvelopeRecovery(t *testing.T) {
	db := testDB(t)
	store := NewWorkflowStore(db)
	reg := NewActivityRegistry()

	var step1Input json.RawMessage
	reg.MustRegister("alloc_port", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{"port":6200}`), nil
	})
	reg.MustRegister("write_compose", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		step1Input = input
		return json.RawMessage(`{"written":true}`), nil
	})

	executor := NewStepExecutor(store, reg)
	saga := NewSagaOrchestrator(store, executor, reg, "test-node")

	steps := []StepDefinition{
		{Name: "alloc_port", Action: "alloc_port"},
		{Name: "write_compose", Action: "write_compose"},
	}
	wf, _ := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "recovery_envelope",
		Version:      1,
		ExternalID:   "env-3",
		Input:        json.RawMessage(`{"stack_name":"myapp"}`),
		Steps:        steps,
	})

	// Simulate crash: pre-complete step 0 with cached output
	allSteps, _ := store.GetWorkflowSteps(wf.ID)
	_ = store.UpdateStepStatus(allSteps[0].ID, StepPending, StepRunning)
	_ = store.UpdateStepStatus(allSteps[0].ID, StepRunning, StepCompleted)
	_ = store.UpdateStepOutput(allSteps[0].ID, json.RawMessage(`{"port":6200}`))

	// Resume execution (step 0 already completed)
	err := saga.Execute(context.Background(), wf)
	if err != nil {
		t.Fatalf("Expected success on resume, got: %v", err)
	}

	// step 1 must have received both workflow.Input AND step 0's cached output
	if step1Input == nil {
		t.Fatal("write_compose did not receive input")
	}
	if !strings.Contains(string(step1Input), "stack_name") {
		t.Errorf("write_compose missing workflow input after recovery; got: %s", string(step1Input))
	}
	if !strings.Contains(string(step1Input), "port") {
		t.Errorf("write_compose missing step 0 cached output after recovery; got: %s", string(step1Input))
	}
}

// TestSagaCompensationReceivesForwardOutput verifies that compensation activities
// receive the forward step's output directly (not wrapped in original_input/original_output).
// This is critical: db.release_port needs {"port":6100}, not {"original_output":{"port":6100}}.
func TestSagaCompensationReceivesForwardOutput(t *testing.T) {
	db := testDB(t)
	store := NewWorkflowStore(db)
	reg := NewActivityRegistry()

	// Step 0: allocate_port → outputs {"port":6100,"app_name":"testapp"}
	reg.MustRegister("allocate_port", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{"port":6100,"app_name":"testapp"}`), nil
	})

	// Step 1: fails permanently → triggers compensation
	reg.MustRegister("deploy_stack", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return nil, NewPermanentError(fmt.Errorf("forced deploy failure"))
	})

	// Compensation for step 0: verify it receives the port directly
	var compensationInput json.RawMessage
	reg.MustRegister("release_port", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		compensationInput = input
		// Parse like the real activity does
		var in struct {
			Port    int    `json:"port"`
			AppName string `json:"app_name"`
		}
		if err := json.Unmarshal(input, &in); err != nil {
			return nil, NewPermanentError(fmt.Errorf("invalid input: %w", err))
		}
		if in.Port == 0 {
			return nil, NewPermanentError(fmt.Errorf("port is required"))
		}
		return json.RawMessage(fmt.Sprintf(`{"port":%d,"released":true}`, in.Port)), nil
	})

	executor := NewStepExecutor(store, reg)
	saga := NewSagaOrchestrator(store, executor, reg, "test-node")

	steps := []StepDefinition{
		{
			Name:       "allocate_port",
			Action:     "allocate_port",
			Compensate: "release_port",
			Retry:      &RetryPolicy{MaxAttempts: 1},
		},
		{
			Name:   "deploy_stack",
			Action: "deploy_stack",
			Retry:  &RetryPolicy{MaxAttempts: 1},
		},
	}
	wf, err := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "comp_input_test",
		Version:      1,
		ExternalID:   "comp-input-1",
		Input:        json.RawMessage(`{"app_name":"testapp"}`),
		Steps:        steps,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = saga.Execute(context.Background(), wf)
	if err != nil {
		t.Fatalf("Expected nil (compensation should succeed), got: %v", err)
	}

	// Verify compensation received the forward step output directly
	if compensationInput == nil {
		t.Fatal("Compensation activity was not called")
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(compensationInput, &parsed); err != nil {
		t.Fatalf("Compensation input is not valid JSON: %v", err)
	}

	// Must have "port" at top level (not nested under "original_output")
	if _, ok := parsed["port"]; !ok {
		t.Errorf("Compensation input missing 'port' at top level; got: %s", string(compensationInput))
	}
	if _, ok := parsed["original_output"]; ok {
		t.Error("Compensation input should NOT have 'original_output' wrapper")
	}

	// Verify step 0 ended in compensated state (not stuck in compensating)
	result, _ := store.GetWorkflow(wf.ID)
	if result.CurrentState != StateCompensated {
		t.Errorf("Expected workflow state=compensated, got %s", result.CurrentState)
	}

	allSteps, _ := store.GetWorkflowSteps(wf.ID)
	if allSteps[0].Status != StepCompensated {
		t.Errorf("Step 0: expected compensated, got %s", allSteps[0].Status)
	}
}

// TestSagaCompensationFailureTerminalState verifies that when compensation fails,
// the step transitions from "compensating" to "failed" (not stuck in "compensating").
func TestSagaCompensationFailureTerminalState(t *testing.T) {
	db := testDB(t)
	store := NewWorkflowStore(db)
	reg := NewActivityRegistry()

	reg.MustRegister("ok_step", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{"done":true}`), nil
	})
	reg.MustRegister("fail_step", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return nil, NewPermanentError(fmt.Errorf("forced failure"))
	})
	reg.MustRegister("fail_compensate", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return nil, NewPermanentError(fmt.Errorf("compensation also fails"))
	})

	executor := NewStepExecutor(store, reg)
	saga := NewSagaOrchestrator(store, executor, reg, "test-node")

	steps := []StepDefinition{
		{Name: "step_0", Action: "ok_step", Compensate: "fail_compensate", Retry: &RetryPolicy{MaxAttempts: 1}},
		{Name: "step_1", Action: "fail_step", Retry: &RetryPolicy{MaxAttempts: 1}},
	}
	wf, _ := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "comp_fail_terminal",
		Version:      1,
		ExternalID:   "comp-fail-term",
		Input:        json.RawMessage(`{}`),
		Steps:        steps,
	})

	err := saga.Execute(context.Background(), wf)
	if err == nil {
		t.Fatal("Expected error from failed compensation")
	}

	// The step whose compensation failed must be in "failed" state, NOT "compensating"
	allSteps, _ := store.GetWorkflowSteps(wf.ID)
	if allSteps[0].Status == StepCompensating {
		t.Errorf("Step 0 stuck in 'compensating' — should transition to 'failed' on compensation failure")
	}
	if allSteps[0].Status != StepFailed {
		t.Errorf("Step 0: expected failed, got %s", allSteps[0].Status)
	}
}

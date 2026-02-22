package flowengine

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestEngineSubmitAndProcess(t *testing.T) {
	db := testDB(t)
	store := NewWorkflowStore(db)
	reg := NewActivityRegistry()

	reg.MustRegister("noop", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{"done":true}`), nil
	})

	engine := NewWorkflowEngine(store, reg, DefaultEngineConfig())

	// Register workflow definition
	def := testWorkflowDef{
		steps: []StepDefinition{
			{Name: "step_0", Action: "noop"},
		},
	}
	if err := engine.RegisterWorkflow(def); err != nil {
		t.Fatal(err)
	}

	// Submit workflow
	wf, err := engine.Submit(context.Background(), SubmitParams{
		WorkflowType: "test_workflow",
		ExternalID:   "submit-1",
		Input:        json.RawMessage(`{"test":"data"}`),
	})
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}
	if wf.ID == "" {
		t.Fatal("Expected non-empty workflow ID")
	}
	if wf.CurrentState != StatePending {
		t.Errorf("Expected pending state, got %s", wf.CurrentState)
	}
}

func TestEngineSubmitUnknownType(t *testing.T) {
	db := testDB(t)
	store := NewWorkflowStore(db)
	reg := NewActivityRegistry()

	engine := NewWorkflowEngine(store, reg, DefaultEngineConfig())

	_, err := engine.Submit(context.Background(), SubmitParams{
		WorkflowType: "nonexistent",
		ExternalID:   "nope",
	})
	if err == nil {
		t.Fatal("Expected error for unknown workflow type")
	}
}

func TestEngineSubmitDuplicate(t *testing.T) {
	db := testDB(t)
	store := NewWorkflowStore(db)
	reg := NewActivityRegistry()

	reg.MustRegister("noop", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{}`), nil
	})

	engine := NewWorkflowEngine(store, reg, DefaultEngineConfig())
	engine.RegisterWorkflow(testWorkflowDef{
		steps: []StepDefinition{{Name: "s", Action: "noop"}},
	})

	// First submit succeeds
	_, err := engine.Submit(context.Background(), SubmitParams{
		WorkflowType: "test_workflow",
		ExternalID:   "dup-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Duplicate submit fails
	_, err = engine.Submit(context.Background(), SubmitParams{
		WorkflowType: "test_workflow",
		ExternalID:   "dup-1",
	})
	if err == nil {
		t.Fatal("Expected ErrDuplicateWorkflow")
	}
}

func TestEngineRegisterDuplicateWorkflow(t *testing.T) {
	db := testDB(t)
	store := NewWorkflowStore(db)
	reg := NewActivityRegistry()

	engine := NewWorkflowEngine(store, reg, DefaultEngineConfig())

	def := testWorkflowDef{}
	if err := engine.RegisterWorkflow(def); err != nil {
		t.Fatal(err)
	}

	err := engine.RegisterWorkflow(def)
	if err == nil {
		t.Fatal("Expected error for duplicate workflow registration")
	}
}

func TestEngineStartStop(t *testing.T) {
	db := testDB(t)
	store := NewWorkflowStore(db)
	reg := NewActivityRegistry()

	config := DefaultEngineConfig()
	config.IdlePollInterval = 50 * time.Millisecond // Fast for testing

	engine := NewWorkflowEngine(store, reg, config)

	ctx := context.Background()
	if err := engine.Start(ctx); err != nil {
		t.Fatal(err)
	}

	if !engine.IsRunning() {
		t.Error("Expected engine to be running")
	}

	// Double start should fail
	if err := engine.Start(ctx); err == nil {
		t.Error("Expected error on double start")
	}

	engine.Stop()

	if engine.IsRunning() {
		t.Error("Expected engine to be stopped")
	}
}

func TestEngineRecovery(t *testing.T) {
	db := testDB(t)
	store := NewWorkflowStore(db)
	reg := NewActivityRegistry()

	reg.MustRegister("noop", func(ctx context.Context, input json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{"done":true}`), nil
	})

	// Create a workflow that simulates a crash mid-execution
	wf, _ := store.CreateWorkflow(CreateWorkflowParams{
		WorkflowType: "test_workflow",
		Version:      1,
		ExternalID:   "recover-1",
		Input:        json.RawMessage(`{}`),
		Steps: []StepDefinition{
			{Name: "step_0", Action: "noop"},
			{Name: "step_1", Action: "noop"},
		},
	})

	// Simulate partially executed state (step 0 completed, workflow running)
	_ = store.UpdateWorkflowState(wf.ID, StateRunning, 0)
	steps, _ := store.GetWorkflowSteps(wf.ID)
	_ = store.UpdateStepStatus(steps[0].ID, StepPending, StepRunning)
	_ = store.UpdateStepStatus(steps[0].ID, StepRunning, StepCompleted)
	_ = store.UpdateStepOutput(steps[0].ID, json.RawMessage(`{"step0":"done"}`))

	// Lock it as if another node was processing
	_, _ = store.LockWorkflow(wf.ID, "old-crashed-node", 5*time.Minute)

	// Create engine — recovery should release the stale lock
	config := DefaultEngineConfig()
	config.ActivePollInterval = 50 * time.Millisecond
	config.IdlePollInterval = 50 * time.Millisecond

	engine := NewWorkflowEngine(store, reg, config)
	engine.RegisterWorkflow(testWorkflowDef{
		steps: []StepDefinition{
			{Name: "step_0", Action: "noop"},
			{Name: "step_1", Action: "noop"},
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := engine.Start(ctx); err != nil {
		t.Fatal(err)
	}

	// Wait for the engine to process the recovered workflow
	time.Sleep(500 * time.Millisecond)
	engine.Stop()

	// Verify the workflow completed
	result, err := store.GetWorkflow(wf.ID)
	if err != nil {
		t.Fatal(err)
	}
	if result.CurrentState != StateCompleted {
		t.Errorf("Expected completed after recovery, got %s", result.CurrentState)
	}
}

func TestEngineNodeID(t *testing.T) {
	db := testDB(t)
	store := NewWorkflowStore(db)
	reg := NewActivityRegistry()

	engine := NewWorkflowEngine(store, reg, DefaultEngineConfig())
	nodeID := engine.NodeID()

	if nodeID == "" {
		t.Error("Expected non-empty node ID")
	}
}

func TestResolveNodeID(t *testing.T) {
	nodeID := resolveNodeID()
	if nodeID == "" {
		t.Error("resolveNodeID returned empty string")
	}
	// In test environment, will likely be hostname since Docker Swarm may not be available
	t.Logf("Resolved node ID: %s", nodeID)
}

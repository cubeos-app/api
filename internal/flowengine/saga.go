package flowengine

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// SagaOrchestrator executes a workflow's steps sequentially (forward path)
// and runs compensation in reverse order on failure (backward path).
//
// Forward path: steps run in order. Each step's output becomes the next step's input.
// Backward path: on failure, compensation runs in reverse for all completed steps.
//
// All state transitions are persisted to the WorkflowStore, making execution
// crash-recoverable. The WorkflowEngine resumes incomplete sagas on startup.
type SagaOrchestrator struct {
	store    *WorkflowStore
	executor *StepExecutor
	registry *ActivityRegistry
	nodeID   string
}

// NewSagaOrchestrator creates a saga orchestrator backed by the given store,
// step executor, and activity registry.
func NewSagaOrchestrator(store *WorkflowStore, executor *StepExecutor, registry *ActivityRegistry, nodeID string) *SagaOrchestrator {
	return &SagaOrchestrator{
		store:    store,
		executor: executor,
		registry: registry,
		nodeID:   nodeID,
	}
}

// Execute runs a workflow through its forward path. If any step fails permanently
// (or exhausts retries), compensation is triggered for all completed steps in
// reverse order. The workflow's final state is one of: completed, failed, compensated.
//
// The method picks up from where the workflow left off — if steps 0-2 are already
// completed (from a previous execution before crash), it continues from step 3.
func (s *SagaOrchestrator) Execute(ctx context.Context, workflow *WorkflowRun) error {
	logger := log.With().
		Str("workflow_id", workflow.ID).
		Str("workflow_type", workflow.WorkflowType).
		Int("version", workflow.Version).
		Logger()

	// If workflow is already compensating (crash during compensation), resume compensation
	if workflow.CurrentState == StateCompensating {
		logger.Info().Msg("Resuming compensation from previous execution")
		return s.compensate(ctx, logger, workflow, workflow.CurrentStep)
	}

	// Transition to running
	if workflow.CurrentState == StatePending {
		if err := s.store.UpdateWorkflowState(workflow.ID, StateRunning, 0); err != nil {
			return fmt.Errorf("transition to running: %w", err)
		}
		s.recordWorkflowEvent(workflow.ID, EventStateChange, string(StatePending), string(StateRunning), "")
	}

	// Get all steps
	steps, err := s.store.GetWorkflowSteps(workflow.ID)
	if err != nil {
		return fmt.Errorf("get workflow steps: %w", err)
	}

	if len(steps) == 0 {
		// No steps — mark completed immediately
		return s.completeWorkflow(logger, workflow, nil)
	}

	// Forward execution: run steps from current position
	var lastOutput json.RawMessage = workflow.Input
	startStep := 0

	// Find the first incomplete step (skip already-completed steps from crash recovery)
	for i, step := range steps {
		if step.Status == StepCompleted {
			// Retrieve cached output for pipeline
			cached, cacheErr := s.store.GetStepOutput(workflow.ID, step.StepIndex)
			if cacheErr == nil && cached != nil {
				lastOutput = cached
			}
			startStep = i + 1
			continue
		}
		break
	}

	// Execute remaining steps
	for i := startStep; i < len(steps); i++ {
		step := steps[i]

		// Update current step index in workflow
		if err := s.store.UpdateWorkflowState(workflow.ID, StateRunning, i); err != nil {
			logger.Error().Err(err).Int("step", i).Msg("Failed to update current step")
		}

		// Build step input: workflow input for first step, previous output for subsequent
		stepInput := lastOutput
		if i == 0 {
			stepInput = workflow.Input
		}

		logger.Info().
			Int("step_index", i).
			Str("step_name", step.StepName).
			Str("activity", step.ActivityName).
			Msg("Executing step")

		result := s.executor.ExecuteStep(ctx, workflow, &step, stepInput)

		if result.Err != nil {
			logger.Error().Err(result.Err).
				Int("step_index", i).
				Str("step_name", step.StepName).
				Msg("Step failed, initiating compensation")

			// Record workflow error
			_ = s.store.UpdateWorkflowError(workflow.ID, StateCompensating, result.Err.Error())
			s.recordWorkflowEvent(workflow.ID, EventStateChange, string(StateRunning), string(StateCompensating),
				fmt.Sprintf("step %d (%s) failed: %v", i, step.StepName, result.Err))

			// Compensate all completed steps in reverse order
			return s.compensate(ctx, logger, workflow, i)
		}

		// Pipeline: pass output to next step
		if result.Output != nil {
			lastOutput = result.Output
		}
	}

	// All steps completed successfully
	return s.completeWorkflow(logger, workflow, lastOutput)
}

// compensate runs compensation for completed steps in reverse order, starting
// from failedAtStep-1 down to 0. Steps that have no compensation activity are skipped.
// Steps that are already compensated (from a previous crash) are skipped.
func (s *SagaOrchestrator) compensate(ctx context.Context, logger zerolog.Logger, workflow *WorkflowRun, failedAtStep int) error {
	steps, err := s.store.GetWorkflowSteps(workflow.ID)
	if err != nil {
		return fmt.Errorf("get steps for compensation: %w", err)
	}

	// Compensate in reverse order from the step before the failed one
	compensateFrom := failedAtStep - 1
	if compensateFrom >= len(steps) {
		compensateFrom = len(steps) - 1
	}

	var compensationErr error
	for i := compensateFrom; i >= 0; i-- {
		step := steps[i]

		// Only compensate steps that completed or were running (crashed mid-execution)
		if step.Status != StepCompleted && step.Status != StepRunning && step.Status != StepFailed {
			continue
		}

		// Skip steps already compensated (crash recovery)
		if step.Status == StepCompensated {
			continue
		}

		// Skip steps with no compensation activity
		if step.CompensateName == "" {
			logger.Debug().
				Int("step_index", i).
				Str("step_name", step.StepName).
				Msg("No compensation defined, skipping")
			continue
		}

		// Update workflow's current step to track progress
		_ = s.store.UpdateWorkflowState(workflow.ID, StateCompensating, i)

		logger.Info().
			Int("step_index", i).
			Str("step_name", step.StepName).
			Str("compensate", step.CompensateName).
			Msg("Compensating step")

		if err := s.executor.ExecuteCompensation(ctx, workflow, &step); err != nil {
			logger.Error().Err(err).
				Int("step_index", i).
				Str("step_name", step.StepName).
				Msg("Compensation failed")
			// Record but continue — compensate remaining steps best-effort
			compensationErr = err
		}
	}

	// Determine final state
	if compensationErr != nil {
		// At least one compensation failed — this is a serious state
		_ = s.store.UpdateWorkflowError(workflow.ID, StateFailed,
			fmt.Sprintf("compensation partially failed: %v", compensationErr))
		s.recordWorkflowEvent(workflow.ID, EventStateChange, string(StateCompensating), string(StateFailed),
			fmt.Sprintf("compensation error: %v", compensationErr))
		return compensationErr
	}

	// All compensations succeeded
	_ = s.store.UpdateWorkflowState(workflow.ID, StateCompensated, 0)
	s.recordWorkflowEvent(workflow.ID, EventStateChange, string(StateCompensating), string(StateCompensated), "all steps compensated")

	logger.Info().Msg("Workflow fully compensated")
	return nil
}

// completeWorkflow marks the workflow as completed with the given output.
func (s *SagaOrchestrator) completeWorkflow(logger zerolog.Logger, workflow *WorkflowRun, output json.RawMessage) error {
	if err := s.store.UpdateWorkflowOutput(workflow.ID, StateCompleted, output); err != nil {
		return fmt.Errorf("mark workflow completed: %w", err)
	}
	s.recordWorkflowEvent(workflow.ID, EventStateChange, string(StateRunning), string(StateCompleted), "")
	logger.Info().Msg("Workflow completed successfully")
	return nil
}

// recordWorkflowEvent is a best-effort event recorder for workflow-level events.
func (s *SagaOrchestrator) recordWorkflowEvent(workflowID string, eventType EventType, oldState, newState, detail string) {
	_ = s.store.RecordEvent(workflowID, nil, eventType, oldState, newState, detail, s.nodeID)
}

// ExecuteWithTimeout runs Execute with a workflow-level timeout.
// Individual step timeouts are handled by the StepExecutor.
func (s *SagaOrchestrator) ExecuteWithTimeout(ctx context.Context, workflow *WorkflowRun, timeout time.Duration) error {
	if timeout <= 0 {
		return s.Execute(ctx, workflow)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return s.Execute(ctx, workflow)
}

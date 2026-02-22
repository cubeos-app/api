package flowengine

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// StepExecutor executes individual workflow steps with retry logic,
// idempotency checking, and activity resolution from the registry.
type StepExecutor struct {
	store    *WorkflowStore
	registry *ActivityRegistry
}

// NewStepExecutor creates a step executor backed by the given store and registry.
func NewStepExecutor(store *WorkflowStore, registry *ActivityRegistry) *StepExecutor {
	return &StepExecutor{
		store:    store,
		registry: registry,
	}
}

// ExecuteStepResult holds the outcome of a step execution.
type ExecuteStepResult struct {
	Output json.RawMessage
	Err    error
	// Skipped is true if the step was already completed (idempotency hit).
	Skipped bool
}

// ExecuteStep runs a single step with retry logic. It:
// 1. Checks if the step is already completed (idempotency cache) — returns cached output
// 2. Resolves the activity function from the registry by name
// 3. Transitions the step to "running"
// 4. Executes the activity with the configured retry policy
// 5. On success: marks step "completed", caches output
// 6. On permanent failure: marks step "failed"
// 7. On transient failure after exhausting retries: marks step "failed"
func (e *StepExecutor) ExecuteStep(ctx context.Context, workflow *WorkflowRun, step *WorkflowStep, input json.RawMessage) ExecuteStepResult {
	logger := log.With().
		Str("workflow_id", workflow.ID).
		Str("workflow_type", workflow.WorkflowType).
		Int("step_index", step.StepIndex).
		Str("step_name", step.StepName).
		Str("activity", step.ActivityName).
		Logger()

	// 1. Idempotency check — if step already completed, return cached output
	if step.Status == StepCompleted {
		logger.Debug().Msg("Step already completed, returning cached output")
		cachedOutput, err := e.store.GetStepOutput(workflow.ID, step.StepIndex)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to retrieve cached step output")
			return ExecuteStepResult{Err: fmt.Errorf("get cached output: %w", err)}
		}
		return ExecuteStepResult{Output: cachedOutput, Skipped: true}
	}

	// 2. Resolve activity from registry
	activityFn, err := e.registry.Get(step.ActivityName)
	if err != nil {
		logger.Error().Err(err).Msg("Activity not found in registry")
		// Activity not found is a permanent error — no point retrying
		e.failStep(step, err)
		return ExecuteStepResult{Err: NewPermanentError(err)}
	}

	// 3. Transition to running
	if err := e.store.UpdateStepStatus(step.ID, StepPending, StepRunning); err != nil {
		// If transition denied, the step may have been modified concurrently
		if IsStepTransitionDenied(err) {
			logger.Warn().Str("current_status", string(step.Status)).Msg("Step status transition denied, may be concurrent execution")
			return ExecuteStepResult{Err: err}
		}
		logger.Error().Err(err).Msg("Failed to transition step to running")
		return ExecuteStepResult{Err: fmt.Errorf("transition to running: %w", err)}
	}

	// Store step input for audit/debug
	if input != nil {
		_ = e.store.UpdateStepInput(step.ID, input)
	}

	// Record event
	e.recordStepEvent(workflow.ID, step.StepIndex, EventStateChange, string(StepPending), string(StepRunning), "")

	// 4. Execute with retry
	retryPolicy := effectiveRetryFromStep(step)
	output, execErr := e.executeWithRetry(ctx, logger, workflow.ID, step, activityFn, input, retryPolicy)

	if execErr != nil {
		// 6/7. Failed — mark step as failed
		logger.Error().Err(execErr).Msg("Step execution failed")
		e.failStep(step, execErr)
		e.recordStepEvent(workflow.ID, step.StepIndex, EventError, string(StepRunning), string(StepFailed), execErr.Error())
		return ExecuteStepResult{Err: execErr}
	}

	// 5. Success — mark step as completed, cache output
	if err := e.store.UpdateStepStatus(step.ID, StepRunning, StepCompleted); err != nil {
		logger.Error().Err(err).Msg("Failed to mark step completed")
		return ExecuteStepResult{Output: output, Err: fmt.Errorf("mark completed: %w", err)}
	}
	if output != nil {
		_ = e.store.UpdateStepOutput(step.ID, output)
	}

	e.recordStepEvent(workflow.ID, step.StepIndex, EventStateChange, string(StepRunning), string(StepCompleted), "")
	logger.Info().Msg("Step completed successfully")

	return ExecuteStepResult{Output: output}
}

// ExecuteCompensation runs a compensation activity for a step.
// Uses the CompensateRetry policy. Compensation must be idempotent.
func (e *StepExecutor) ExecuteCompensation(ctx context.Context, workflow *WorkflowRun, step *WorkflowStep) error {
	logger := log.With().
		Str("workflow_id", workflow.ID).
		Int("step_index", step.StepIndex).
		Str("step_name", step.StepName).
		Str("compensate", step.CompensateName).
		Logger()

	if step.CompensateName == "" {
		logger.Debug().Msg("No compensation activity defined, skipping")
		return nil
	}

	// Resolve compensation activity
	compensateFn, err := e.registry.Get(step.CompensateName)
	if err != nil {
		logger.Error().Err(err).Msg("Compensation activity not found")
		return NewPermanentError(err)
	}

	// Transition to compensating
	if err := e.store.UpdateStepStatus(step.ID, StepCompleted, StepCompensating); err != nil {
		// Also try from failed state (compensation can run on failed steps too)
		if err2 := e.store.UpdateStepStatus(step.ID, StepFailed, StepCompensating); err2 != nil {
			// Try from running state (crash during execution)
			if err3 := e.store.UpdateStepStatus(step.ID, StepRunning, StepCompensating); err3 != nil {
				logger.Warn().Err(err).Msg("Could not transition step to compensating")
			}
		}
	}

	e.recordStepEvent(workflow.ID, step.StepIndex, EventCompensation, string(step.Status), string(StepCompensating), "")

	// Build compensation input from the step's original input + output
	compensateInput := buildCompensationInput(step)

	// Execute compensation with its own retry policy
	retryPolicy := effectiveCompensateRetryFromStep(step)
	_, execErr := e.executeWithRetry(ctx, logger, workflow.ID, step, compensateFn, compensateInput, retryPolicy)

	if execErr != nil {
		logger.Error().Err(execErr).Msg("Compensation failed")
		_ = e.store.UpdateStepError(step.ID, execErr.Error())
		e.recordStepEvent(workflow.ID, step.StepIndex, EventError, string(StepCompensating), string(StepFailed), execErr.Error())
		return execErr
	}

	// Mark compensated
	_ = e.store.UpdateStepStatus(step.ID, StepCompensating, StepCompensated)
	e.recordStepEvent(workflow.ID, step.StepIndex, EventCompensation, string(StepCompensating), string(StepCompensated), "")

	logger.Info().Msg("Step compensated successfully")
	return nil
}

// executeWithRetry runs an activity function with exponential backoff retry.
// Only retries on transient errors. Permanent errors fail immediately.
func (e *StepExecutor) executeWithRetry(
	ctx context.Context,
	logger zerolog.Logger,
	workflowID string,
	step *WorkflowStep,
	fn ActivityFunc,
	input json.RawMessage,
	policy RetryPolicy,
) (json.RawMessage, error) {
	maxAttempts := policy.MaxAttempts
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			// Exponential backoff: initialInterval * 2^(attempt-1), capped at maxInterval
			delay := policy.InitialInterval
			for i := 1; i < attempt; i++ {
				delay *= 2
				if delay > policy.MaxInterval {
					delay = policy.MaxInterval
					break
				}
			}

			// Record retry event
			e.recordStepEvent(workflowID, step.StepIndex, EventRetry, "", "",
				fmt.Sprintf("attempt %d/%d, backoff %v", attempt+1, maxAttempts, delay))

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		// Execute the activity with a per-attempt timeout
		output, err := e.executeOnce(ctx, fn, input, step)
		if err == nil {
			return output, nil
		}

		lastErr = ClassifyError(err)

		// Permanent errors fail immediately — no retry
		if IsPermanent(lastErr) {
			return nil, lastErr
		}

		// Transient error — retry if attempts remain
		// (log is handled by the retry event above)
	}

	return nil, fmt.Errorf("exhausted %d attempts: %w", maxAttempts, lastErr)
}

// executeOnce runs a single attempt of an activity with timeout.
func (e *StepExecutor) executeOnce(ctx context.Context, fn ActivityFunc, input json.RawMessage, step *WorkflowStep) (json.RawMessage, error) {
	// Determine timeout from step definition metadata or use default
	timeout := DefaultStepTimeout
	// The step's timeout is set from the StepDefinition at workflow creation time,
	// but we don't store timeout in the DB (it's part of the definition).
	// For now, use the default. The saga orchestrator can override via context.

	stepCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return fn(stepCtx, input)
}

// failStep marks a step as failed in the store.
func (e *StepExecutor) failStep(step *WorkflowStep, err error) {
	_ = e.store.UpdateStepError(step.ID, err.Error())
	// Try transition from running → failed
	if transErr := e.store.UpdateStepStatus(step.ID, StepRunning, StepFailed); transErr != nil {
		// If that fails, try from pending (activity resolution failure before running)
		_ = e.store.UpdateStepStatus(step.ID, StepPending, StepFailed)
	}
}

// recordStepEvent is a best-effort event recorder.
func (e *StepExecutor) recordStepEvent(workflowID string, stepIndex int, eventType EventType, oldState, newState, detail string) {
	_ = e.store.RecordEvent(workflowID, &stepIndex, eventType, oldState, newState, detail, "")
}

// IsStepTransitionDenied checks if an error is a step transition denial.
func IsStepTransitionDenied(err error) bool {
	if err == nil {
		return false
	}
	return err == ErrStepTransitionDenied || fmt.Sprintf("%v", err) == ErrStepTransitionDenied.Error() ||
		(len(err.Error()) > 0 && findSubstring(err.Error(), "step status transition denied"))
}

// effectiveRetryFromStep builds a RetryPolicy for a step.
// In the foundation layer, we use defaults. The saga orchestrator will
// supply step-specific policies from the WorkflowDefinition when executing.
func effectiveRetryFromStep(step *WorkflowStep) RetryPolicy {
	return DefaultRetryPolicy
}

// effectiveCompensateRetryFromStep returns the compensation retry policy.
func effectiveCompensateRetryFromStep(step *WorkflowStep) RetryPolicy {
	return DefaultCompensateRetryPolicy
}

// buildCompensationInput builds the input for a compensation activity.
// It combines the step's original input and output into a single JSON object,
// giving the compensation all the context it needs to reverse the action.
func buildCompensationInput(step *WorkflowStep) json.RawMessage {
	type compInput struct {
		OriginalInput  json.RawMessage `json:"original_input,omitempty"`
		OriginalOutput json.RawMessage `json:"original_output,omitempty"`
	}
	data, err := json.Marshal(compInput{
		OriginalInput:  step.Input,
		OriginalOutput: step.Output,
	})
	if err != nil {
		return nil
	}
	return data
}

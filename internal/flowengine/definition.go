package flowengine

import (
	"context"
	"encoding/json"
	"time"
)

// ActivityFunc is the signature for all workflow activities.
// Activities receive a context (with timeout/cancellation) and a JSON input,
// and return a JSON output or an error. Errors should be wrapped as
// TransientError or PermanentError for proper retry classification.
type ActivityFunc func(ctx context.Context, input json.RawMessage) (json.RawMessage, error)

// WorkflowDefinition describes a workflow type with its steps.
// Implementations are registered once at startup and referenced by type string.
type WorkflowDefinition interface {
	// Type returns the unique workflow type identifier (e.g., "app_install", "app_remove").
	Type() string

	// Version returns the workflow definition version. When the step sequence changes,
	// bump this. In-flight workflows from older versions continue executing their
	// original steps (stored in workflow_steps at creation time).
	Version() int

	// Steps returns the ordered list of step definitions for this workflow.
	// Each step references activities by name (resolved from ActivityRegistry at runtime).
	Steps() []StepDefinition
}

// StepDefinition describes a single step in a workflow.
type StepDefinition struct {
	// Name is a human-readable label for this step (e.g., "deploy_stack", "add_dns").
	Name string

	// Action is the activity name to execute (resolved from ActivityRegistry).
	// Example: "docker.deploy_stack", "infra.add_dns"
	Action string

	// Compensate is the activity name to execute during rollback (optional).
	// If empty, this step has no compensation. Example: "docker.remove_stack"
	Compensate string

	// Retry controls retry behavior for this step's action.
	// If nil, DefaultRetryPolicy is used.
	Retry *RetryPolicy

	// CompensateRetry controls retry behavior for this step's compensation.
	// If nil, DefaultCompensateRetryPolicy is used.
	CompensateRetry *RetryPolicy

	// Timeout is the maximum duration for a single execution attempt of this step.
	// If zero, DefaultStepTimeout is used.
	Timeout time.Duration
}

// RetryPolicy controls how a step or compensation is retried on transient failures.
type RetryPolicy struct {
	// MaxAttempts is the total number of attempts (including the first try).
	// 1 means no retry. 0 uses the default.
	MaxAttempts int

	// InitialInterval is the base delay between retries.
	// Actual delay = InitialInterval * 2^attempt, capped at MaxInterval.
	InitialInterval time.Duration

	// MaxInterval caps the exponential backoff delay.
	MaxInterval time.Duration
}

// Defaults
var (
	// DefaultRetryPolicy is used when a StepDefinition has no explicit Retry.
	DefaultRetryPolicy = RetryPolicy{
		MaxAttempts:     3,
		InitialInterval: 1 * time.Second,
		MaxInterval:     10 * time.Second,
	}

	// DefaultCompensateRetryPolicy is used for compensation steps.
	// More aggressive retries because compensation must succeed for consistency.
	DefaultCompensateRetryPolicy = RetryPolicy{
		MaxAttempts:     5,
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     5 * time.Second,
	}

	// DefaultStepTimeout is the per-attempt timeout when none is specified.
	DefaultStepTimeout = 90 * time.Second
)

// EffectiveRetry returns the retry policy for this step, falling back to DefaultRetryPolicy.
func (s StepDefinition) EffectiveRetry() RetryPolicy {
	if s.Retry != nil {
		return *s.Retry
	}
	return DefaultRetryPolicy
}

// EffectiveCompensateRetry returns the compensation retry policy, falling back to default.
func (s StepDefinition) EffectiveCompensateRetry() RetryPolicy {
	if s.CompensateRetry != nil {
		return *s.CompensateRetry
	}
	return DefaultCompensateRetryPolicy
}

// EffectiveTimeout returns the step timeout, falling back to DefaultStepTimeout.
func (s StepDefinition) EffectiveTimeout() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return DefaultStepTimeout
}

// WorkflowState represents the lifecycle state of a workflow run.
type WorkflowState string

const (
	StatePending      WorkflowState = "pending"
	StateRunning      WorkflowState = "running"
	StateCompensating WorkflowState = "compensating"
	StateCompleted    WorkflowState = "completed"
	StateFailed       WorkflowState = "failed"
	StateCompensated  WorkflowState = "compensated"
)

// IsTerminal returns true if the workflow is in a final state.
func (s WorkflowState) IsTerminal() bool {
	return s == StateCompleted || s == StateFailed || s == StateCompensated
}

// StepStatus represents the lifecycle state of a single workflow step.
type StepStatus string

const (
	StepPending      StepStatus = "pending"
	StepRunning      StepStatus = "running"
	StepCompleted    StepStatus = "completed"
	StepFailed       StepStatus = "failed"
	StepSkipped      StepStatus = "skipped"
	StepCompensating StepStatus = "compensating"
	StepCompensated  StepStatus = "compensated"
)

// EventType represents the type of workflow event recorded in the audit log.
type EventType string

const (
	EventStateChange  EventType = "state_change"
	EventRetry        EventType = "retry"
	EventCompensation EventType = "compensation"
	EventError        EventType = "error"
)

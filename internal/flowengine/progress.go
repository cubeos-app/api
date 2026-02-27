package flowengine

import (
	"context"
	"fmt"
	"time"
)

// ProgressEmitter is the interface that a Job must satisfy for the ProgressAdapter.
// Matched by *managers.Job so the adapter bridges FlowEngine → SSE without
// importing the managers package from here.
type ProgressEmitter interface {
	Emit(step string, progress int, detail string)
	EmitError(step string, progress int, errMsg string)
	EmitDone(detail string, appURL ...string)
}

// stepProgress maps workflow step names to SSE progress percentages.
// Mirrors the SSE progress flow for appstore_install and related workflows.
var stepProgress = map[string]int{
	"validate":         10,
	"read_manifest":    15,
	"allocate_port":    20,
	"process_manifest": 25,
	"create_dirs":      30,
	"remap_volumes":    32,
	"write_compose":    35,
	"deploy_stack":     50,
	"wait_convergence": 70,
	"add_dns":          80,
	"create_proxy":     85,
	"insert_db":        90,
	"cache_retag":      91,
	"cache_push":       92,
	"cache_manifest":   93,
	"store_volumes":    95,
	"detect_webui":     97,
	"health_check":     99,

	// access_profile_switch workflow steps
	"validate_transition":    10,
	"pause_app_updates":      15,
	"teardown_old_access":    25,
	"update_profile_db":      35,
	"configure_new_services": 45,
	"migrate_app_entries":    80,
	"verify_access":          95,
	"resume_app_updates":     99,
}

// ProgressAdapter translates FlowEngine step status changes into SSE progress events.
// It wraps a ProgressEmitter (typically a *managers.Job) and emits the appropriate
// Emit/EmitError/EmitDone calls as the workflow progresses.
//
// Usage:
//
//	adapter := flowengine.NewProgressAdapter(job)
//	engine.OnCompletion(workflows.AppStoreInstallType, adapter.OnWorkflowComplete)
type ProgressAdapter struct {
	emitter ProgressEmitter
}

// NewProgressAdapter creates a ProgressAdapter that forwards step events to emitter.
func NewProgressAdapter(emitter ProgressEmitter) *ProgressAdapter {
	return &ProgressAdapter{emitter: emitter}
}

// OnStepStart emits a "running" progress event when a step begins.
func (p *ProgressAdapter) OnStepStart(stepName string) {
	pct := stepProgressPct(stepName)
	p.emitter.Emit(stepName, pct, "")
}

// OnStepComplete emits a progress event when a step finishes successfully.
func (p *ProgressAdapter) OnStepComplete(stepName string) {
	pct := stepProgressPct(stepName)
	p.emitter.Emit(stepName, pct, "")
}

// OnStepFail emits an error progress event when a step fails.
func (p *ProgressAdapter) OnStepFail(stepName string, errMsg string) {
	pct := stepProgressPct(stepName)
	p.emitter.EmitError(stepName, pct, errMsg)
}

// OnWorkflowComplete emits the terminal event. If state is completed, EmitDone
// is called with the app URL from the workflow output (if available).
// For any other terminal state (failed, compensated), EmitError is emitted.
func (p *ProgressAdapter) OnWorkflowComplete(workflowType, externalID string, state WorkflowState) {
	switch state {
	case StateCompleted:
		p.emitter.EmitDone("Installation complete")
	default:
		p.emitter.EmitError("failed", 0, string(state))
	}
}

// PollAndEmit polls the WorkflowStore for step status changes and emits SSE progress events
// to the wrapped ProgressEmitter. Blocks until the workflow reaches a terminal state.
//
// Returns nil if the workflow completed successfully, or an error if it failed/compensated.
// The caller is responsible for emitting EmitDone/EmitError after this returns.
func (p *ProgressAdapter) PollAndEmit(ctx context.Context, store *WorkflowStore, workflowID string) error {
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	emitted := make(map[string]StepStatus) // track last-known status per step

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		wf, err := store.GetWorkflow(workflowID)
		if err != nil {
			continue
		}

		steps, err := store.GetWorkflowSteps(workflowID)
		if err != nil {
			continue
		}

		for _, step := range steps {
			prev, seen := emitted[step.StepName]
			if seen && prev == step.Status {
				continue
			}
			emitted[step.StepName] = step.Status

			switch step.Status {
			case StepRunning:
				p.OnStepStart(step.StepName)
			case StepCompleted:
				p.OnStepComplete(step.StepName)
			case StepFailed:
				p.OnStepFail(step.StepName, step.Error)
			}
		}

		switch wf.CurrentState {
		case StateCompleted:
			return nil
		case StateFailed, StateCompensated:
			msg := wf.Error
			if msg == "" {
				msg = string(wf.CurrentState)
			}
			return fmt.Errorf("workflow %s", msg)
		}
	}
}

// WaitForCompletion polls the WorkflowStore until the workflow reaches a terminal state.
// Unlike PollAndEmit, it emits no SSE events. Useful for synchronous callers.
//
// Returns nil on success, error on failure/compensation.
func WaitForCompletion(ctx context.Context, store *WorkflowStore, workflowID string) error {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		wf, err := store.GetWorkflow(workflowID)
		if err != nil {
			continue
		}

		switch wf.CurrentState {
		case StateCompleted:
			return nil
		case StateFailed, StateCompensated:
			msg := wf.Error
			if msg == "" {
				msg = string(wf.CurrentState)
			}
			return fmt.Errorf("workflow %s", msg)
		}
	}
}

// stepProgressPct returns the SSE progress percentage for a step name.
// Unknown step names default to 50.
func stepProgressPct(stepName string) int {
	if pct, ok := stepProgress[stepName]; ok {
		return pct
	}
	return 50
}

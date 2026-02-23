package flowengine

// ProgressEmitter is the interface that a Job must satisfy for the ProgressAdapter.
// Matched by *managers.Job so the adapter bridges FlowEngine → SSE without
// importing the managers package from here.
type ProgressEmitter interface {
	Emit(step string, progress int, detail string)
	EmitError(step string, progress int, errMsg string)
	EmitDone(detail string, appURL ...string)
}

// stepProgress maps workflow step names to SSE progress percentages.
// Mirrors the 10-step SSE flow from InstallAppWithProgress().
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
	"create_proxy":     90,
	"insert_db":        95,
	"store_volumes":    97,
	"detect_webui":     98,
	"health_check":     99,
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

// stepProgressPct returns the SSE progress percentage for a step name.
// Unknown step names default to 50.
func stepProgressPct(stepName string) int {
	if pct, ok := stepProgress[stepName]; ok {
		return pct
	}
	return 50
}

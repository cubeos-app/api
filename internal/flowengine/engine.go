package flowengine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// DefaultEngineConfig returns sensible engine defaults for CubeOS.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		ActivePollInterval: 200 * time.Millisecond,
		IdlePollInterval:   2 * time.Second,
		ReaperInterval:     30 * time.Second,
		LockDuration:       2 * time.Minute,
		WorkflowTimeout:    10 * time.Minute,
	}
}

// EngineConfig holds tunable parameters for the WorkflowEngine.
type EngineConfig struct {
	// ActivePollInterval is how often the engine polls for pending workflows
	// when there are active (non-terminal) workflows in the system.
	ActivePollInterval time.Duration

	// IdlePollInterval is how often the engine polls when no active workflows exist.
	IdlePollInterval time.Duration

	// ReaperInterval is how often the reaper checks for stuck locks.
	ReaperInterval time.Duration

	// LockDuration is how long a workflow lock is held before the reaper can release it.
	LockDuration time.Duration

	// WorkflowTimeout is the maximum time a single workflow execution can run.
	WorkflowTimeout time.Duration
}

// CompletionHook is called when a workflow reaches a terminal state (completed/failed).
// Fired asynchronously after the workflow finishes.
type CompletionHook func(workflowType, externalID string, state WorkflowState)

// WorkflowEngine is the main entry point for the FlowEngine subsystem.
// It manages the lifecycle of workflows: submission, polling, execution,
// recovery on startup, and lock reaping.
//
// The engine runs two background goroutines:
//   - pollLoop: picks pending workflows, locks them, and executes via SagaOrchestrator
//   - reaperLoop: releases expired locks so crashed workflows can be retried
//
// Thread-safety: Submit() is safe for concurrent use. The poll loop is single-threaded
// (one workflow at a time) to avoid SQLite contention on the Pi's SD card.
type WorkflowEngine struct {
	store    *WorkflowStore
	saga     *SagaOrchestrator
	registry *ActivityRegistry
	config   EngineConfig
	nodeID   string

	// definitions maps workflow type strings to their definitions.
	// Populated at startup via RegisterWorkflow().
	definitions map[string]WorkflowDefinition
	defMu       sync.RWMutex

	// completionHooks maps workflow type strings to hooks fired on terminal state.
	completionHooks map[string]CompletionHook
	hookMu          sync.RWMutex

	// running tracks whether the engine is started.
	running atomic.Bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// NewWorkflowEngine creates a new engine. Call RegisterWorkflow() to add workflow
// definitions, then Start() to begin processing.
func NewWorkflowEngine(store *WorkflowStore, registry *ActivityRegistry, config EngineConfig) *WorkflowEngine {
	nodeID := resolveNodeID()

	executor := NewStepExecutor(store, registry)
	saga := NewSagaOrchestrator(store, executor, registry, nodeID)

	return &WorkflowEngine{
		store:           store,
		saga:            saga,
		registry:        registry,
		config:          config,
		nodeID:          nodeID,
		definitions:     make(map[string]WorkflowDefinition),
		completionHooks: make(map[string]CompletionHook),
	}
}

// RegisterWorkflow adds a workflow definition to the engine.
// Must be called before Start(). Not safe for concurrent use.
func (e *WorkflowEngine) RegisterWorkflow(def WorkflowDefinition) error {
	e.defMu.Lock()
	defer e.defMu.Unlock()

	wfType := def.Type()
	if _, exists := e.definitions[wfType]; exists {
		return fmt.Errorf("workflow type %q already registered", wfType)
	}
	e.definitions[wfType] = def

	log.Info().
		Str("type", wfType).
		Int("version", def.Version()).
		Int("steps", len(def.Steps())).
		Msg("Registered workflow definition")

	return nil
}

// getDefinition returns a registered workflow definition by type.
func (e *WorkflowEngine) getDefinition(wfType string) (WorkflowDefinition, bool) {
	e.defMu.RLock()
	defer e.defMu.RUnlock()
	def, ok := e.definitions[wfType]
	return def, ok
}

// OnCompletion registers a hook that fires when a workflow of the given type
// reaches a terminal state (completed or failed). The hook runs in a separate
// goroutine to avoid blocking the poll loop.
// Use this for cache invalidation, catalog refresh, notification delivery, etc.
func (e *WorkflowEngine) OnCompletion(workflowType string, hook CompletionHook) {
	e.hookMu.Lock()
	defer e.hookMu.Unlock()
	e.completionHooks[workflowType] = hook
	log.Info().Str("type", workflowType).Msg("Registered completion hook")
}

// fireCompletionHook fires the registered hook for a workflow type, if any.
// Runs asynchronously. Panics in the hook are recovered and logged.
func (e *WorkflowEngine) fireCompletionHook(workflowType, externalID string, state WorkflowState) {
	e.hookMu.RLock()
	hook, ok := e.completionHooks[workflowType]
	e.hookMu.RUnlock()
	if !ok {
		return
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error().
					Interface("panic", r).
					Str("type", workflowType).
					Str("external_id", externalID).
					Msg("Completion hook panicked")
			}
		}()
		hook(workflowType, externalID, state)
	}()
}

// SubmitParams holds parameters for submitting a new workflow.
type SubmitParams struct {
	WorkflowType string
	ExternalID   string          // idempotency key (e.g., app name)
	Input        json.RawMessage // workflow-level input
	Metadata     json.RawMessage // extensible JSON bag
	MaxRetries   int             // 0 = default (3)
}

// Submit creates a new workflow and enqueues it for execution.
// Returns ErrDuplicateWorkflow if an active workflow with the same type+external_id exists.
// The UNIQUE partial index on workflow_runs enforces this at the database level.
func (e *WorkflowEngine) Submit(ctx context.Context, params SubmitParams) (*WorkflowRun, error) {
	def, ok := e.getDefinition(params.WorkflowType)
	if !ok {
		return nil, fmt.Errorf("unknown workflow type: %s", params.WorkflowType)
	}

	createParams := CreateWorkflowParams{
		WorkflowType: params.WorkflowType,
		Version:      def.Version(),
		ExternalID:   params.ExternalID,
		Input:        params.Input,
		Metadata:     params.Metadata,
		MaxRetries:   params.MaxRetries,
		Steps:        def.Steps(),
	}

	wf, err := e.store.CreateWorkflow(createParams)
	if err != nil {
		return nil, err
	}

	log.Info().
		Str("workflow_id", wf.ID).
		Str("type", params.WorkflowType).
		Str("external_id", params.ExternalID).
		Msg("Workflow submitted")

	return wf, nil
}

// Start begins the engine's background processing. It:
// 1. Recovers any incomplete workflows from a previous crash
// 2. Starts the poll loop goroutine
// 3. Starts the reaper goroutine
//
// Call Stop() to shut down gracefully.
func (e *WorkflowEngine) Start(ctx context.Context) error {
	if e.running.Load() {
		return fmt.Errorf("engine already running")
	}

	ctx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	e.running.Store(true)

	log.Info().
		Str("node_id", e.nodeID).
		Dur("active_poll", e.config.ActivePollInterval).
		Dur("idle_poll", e.config.IdlePollInterval).
		Dur("reaper", e.config.ReaperInterval).
		Msg("Starting FlowEngine")

	// Recover incomplete workflows
	if err := e.recover(ctx); err != nil {
		log.Error().Err(err).Msg("FlowEngine recovery failed (continuing)")
	}

	// Start poll loop
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.pollLoop(ctx)
	}()

	// Start reaper
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.reaperLoop(ctx)
	}()

	return nil
}

// Stop gracefully shuts down the engine. Blocks until all goroutines exit.
func (e *WorkflowEngine) Stop() {
	if !e.running.Load() {
		return
	}
	log.Info().Msg("Stopping FlowEngine")
	e.cancel()
	e.wg.Wait()
	e.running.Store(false)
	log.Info().Msg("FlowEngine stopped")
}

// IsRunning returns whether the engine is currently processing.
func (e *WorkflowEngine) IsRunning() bool {
	return e.running.Load()
}

// NodeID returns the engine's node identifier (Swarm node ID or hostname).
func (e *WorkflowEngine) NodeID() string {
	return e.nodeID
}

// recover picks up incomplete workflows from a previous crash.
// Workflows in pending/running/compensating state are re-executed.
func (e *WorkflowEngine) recover(ctx context.Context) error {
	incomplete, err := e.store.GetIncompleteWorkflows()
	if err != nil {
		return fmt.Errorf("query incomplete workflows: %w", err)
	}

	if len(incomplete) == 0 {
		log.Debug().Msg("No incomplete workflows to recover")
		return nil
	}

	log.Info().Int("count", len(incomplete)).Msg("Recovering incomplete workflows")

	for _, wf := range incomplete {
		// Release any stale locks from previous node
		_ = e.store.UnlockWorkflow(wf.ID)

		// Re-execute in the poll loop — don't block startup
		log.Info().
			Str("workflow_id", wf.ID).
			Str("type", wf.WorkflowType).
			Str("state", string(wf.CurrentState)).
			Int("step", wf.CurrentStep).
			Msg("Marked workflow for recovery")
	}

	return nil
}

// pollLoop continuously checks for pending workflows and executes them.
// Uses adaptive polling: fast when active workflows exist, slow when idle.
func (e *WorkflowEngine) pollLoop(ctx context.Context) {
	log.Debug().Msg("FlowEngine poll loop started")

	for {
		interval := e.config.IdlePollInterval

		// Check for active workflows to determine poll speed
		incomplete, err := e.store.GetIncompleteWorkflows()
		if err != nil {
			log.Error().Err(err).Msg("Poll loop: failed to query incomplete workflows")
		} else if len(incomplete) > 0 {
			interval = e.config.ActivePollInterval
		}

		// Try to pick and execute a workflow
		if err == nil && len(incomplete) > 0 {
			e.processNextWorkflow(ctx, incomplete)
		}

		select {
		case <-ctx.Done():
			log.Debug().Msg("FlowEngine poll loop stopped")
			return
		case <-time.After(interval):
		}
	}
}

// processNextWorkflow attempts to lock and execute the first available workflow.
func (e *WorkflowEngine) processNextWorkflow(ctx context.Context, candidates []WorkflowRun) {
	for _, wf := range candidates {
		// Try to acquire lock
		locked, err := e.store.LockWorkflow(wf.ID, e.nodeID, e.config.LockDuration)
		if err != nil {
			log.Error().Err(err).Str("workflow_id", wf.ID).Msg("Failed to lock workflow")
			continue
		}
		if !locked {
			// Another node has the lock
			continue
		}

		// Check that we have the workflow definition
		_, ok := e.getDefinition(wf.WorkflowType)
		if !ok {
			log.Warn().
				Str("workflow_id", wf.ID).
				Str("type", wf.WorkflowType).
				Msg("No definition registered for workflow type, skipping")
			_ = e.store.UnlockWorkflow(wf.ID)
			continue
		}

		// Execute with timeout
		log.Info().
			Str("workflow_id", wf.ID).
			Str("type", wf.WorkflowType).
			Str("state", string(wf.CurrentState)).
			Msg("Executing workflow")

		execErr := e.saga.ExecuteWithTimeout(ctx, &wf, e.config.WorkflowTimeout)
		if execErr != nil {
			log.Error().Err(execErr).
				Str("workflow_id", wf.ID).
				Msg("Workflow execution error")
		}

		// Release lock
		_ = e.store.UnlockWorkflow(wf.ID)

		// Check if workflow reached terminal state and fire completion hook
		updated, getErr := e.store.GetWorkflow(wf.ID)
		if getErr == nil && updated != nil && updated.CurrentState.IsTerminal() {
			e.fireCompletionHook(updated.WorkflowType, updated.ExternalID, updated.CurrentState)
		}

		// Process one at a time (single-threaded to avoid SQLite contention)
		return
	}
}

// reaperLoop periodically releases expired workflow locks.
// If a node crashes while holding a lock, the reaper on any node will release it
// after the lock expires, allowing the workflow to be picked up again.
func (e *WorkflowEngine) reaperLoop(ctx context.Context) {
	log.Debug().Msg("FlowEngine reaper started")

	for {
		select {
		case <-ctx.Done():
			log.Debug().Msg("FlowEngine reaper stopped")
			return
		case <-time.After(e.config.ReaperInterval):
		}

		released, err := e.store.ReleaseExpiredLocks()
		if err != nil {
			log.Error().Err(err).Msg("Reaper: failed to release expired locks")
			continue
		}
		if released > 0 {
			log.Info().Int64("released", released).Msg("Reaper: released expired workflow locks")
		}
	}
}

// resolveNodeID determines the node identifier for lock ownership.
// Prefers the Docker Swarm node ID (stable across restarts), falls back to hostname.
func resolveNodeID() string {
	// Try Swarm node ID first
	cmd := exec.Command("docker", "info", "--format", "{{.Swarm.NodeID}}")
	out, err := cmd.Output()
	if err == nil {
		nodeID := strings.TrimSpace(string(out))
		if nodeID != "" {
			log.Debug().Str("node_id", nodeID).Msg("Resolved Swarm node ID")
			return nodeID
		}
	}

	// Fall back to hostname
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	log.Debug().Str("node_id", hostname).Msg("Swarm node ID not available, using hostname")
	return hostname
}

Feature: WorkflowEngine (spec/001 — RETROSPECTIVE)

  # Covers: REQ-100, REQ-102, REQ-103, REQ-104, REQ-105, REQ-106, REQ-108, REQ-109, REQ-110, REQ-111, REQ-112, REQ-114, REQ-115

  Scenario: WorkflowEngine type exists with documented fields
    When inspecting internal/flowengine/engine.go:61
    Then the WorkflowEngine struct has fields: store, saga, registry, config, nodeID, definitions, completionHooks, running, cancel, wg

  Scenario: RegisterWorkflow rejects duplicate types
    Given engine has "appstore_install" registered
    When code tries to register "appstore_install" again
    Then RegisterWorkflow returns error "workflow type \"appstore_install\" already registered"

  Scenario: Start begins poll + reaper goroutines
    When engine.Start(ctx) is called
    Then the running atomic.Bool is true
    And pollLoop goroutine is active
    And reaperLoop goroutine is active

  Scenario: Stop gracefully shuts down
    When engine.Stop() is called
    Then context is cancelled
    And all goroutines exit within sync.WaitGroup wait
    And running atomic.Bool is false

  Scenario: Adaptive polling
    Given GetIncompleteWorkflows returns 5 active workflows
    When the next poll tick fires
    Then the next interval is ActivePollInterval (not IdlePollInterval)

  Scenario: Reaper releases expired locks
    Given a workflow lock has been held longer than LockDuration
    When the reaper fires
    Then store.ReleaseExpiredLocks() is called
    And the lock is released

  Scenario: Recover unlocks incomplete workflows on Start
    Given workflows in pending/running/compensating state exist with stale locks from a previous node
    When engine.Start(ctx) runs recovery
    Then UnlockWorkflow(wf.ID) is called for each
    And the poll loop picks them up

  Scenario: Completion hook fires async with panic recovery
    Given a registered completion hook for "appstore_install"
    When the workflow reaches terminal state
    Then the hook fires in a separate goroutine
    And a panic inside the hook is recovered + logged (engine survives)

  Scenario: Single-threaded processing per node
    When pollLoop picks 5 candidate workflows
    Then processNextWorkflow processes exactly one then returns
    And the next poll cycle picks the next workflow

  Scenario: Idempotent submission via UNIQUE partial index
    Given a workflow with external_id="abc" was submitted and is still running
    When Submit is called again with the same workflow_type + external_id
    Then store.CreateWorkflow returns ErrUniqueViolation
    And the engine surfaces this as a clean "workflow already exists" error

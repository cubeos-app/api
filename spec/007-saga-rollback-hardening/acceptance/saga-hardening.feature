Feature: Saga rollback hardening (spec/007)

  # REQ-700 + REQ-701 + REQ-703 — crash recovery
  Scenario: Mid-saga process kill triggers crash recovery on next boot
    Given a saga is mid-step 5 of 9 and the api process is killed
    When api restarts
    Then crash-recovery detects the incomplete run
    And compensating actions for steps 1-4 run in reverse
    And the run is marked status=crashed

  # REQ-704 — manual cleanup
  Scenario: Compensation failing twice marks requires_operator
    Given step 3's Compensate fails twice consecutively (initial + retry)
    When the runner gives up
    Then flowengine_runs.requires_operator = true for that run
    And operator_notes is empty (operator will fill in)

  # REQ-705 + REQ-706
  Scenario: Operator queries + resolves requires_operator runs
    When the operator GETs /api/v1/flowengine/runs?requires_operator=true
    Then the response includes all unresolved manual-cleanup runs
    When the operator POSTs /api/v1/flowengine/runs/{id}/resolve with {notes:"cleaned up DNS manually"}
    Then the run's resolved_at is set and operator_notes is recorded

  # REQ-707 — step timeout
  Scenario: Step exceeding declared timeout triggers compensation
    Given a step with Timeout: 5 seconds taking 10 seconds
    When the runner observes the timeout
    Then ErrStepTimeout is returned
    And compensation runs for prior steps

  # REQ-711 — concurrency cap
  Scenario: 6th concurrent saga queues
    Given 5 sagas are running and CUBEOS_MAX_CONCURRENT_SAGAS=5
    When a 6th install arrives
    Then the request queues in Orchestrator.requestQueue
    And it starts once one of the 5 finishes
    And if waited > 30s, returns HTTP 503

  # REQ-712 + REQ-713 + REQ-714 — retry
  Scenario: Step with MaxRetries retries with exponential backoff
    Given a step with MaxRetries: 3 fails on first attempt
    When the runner retries
    Then attempts happen at 250ms, 500ms, 1s after each failure
    And audit log records each attempt
    And if 4th attempt also fails, compensation kicks in

  # REQ-708 + REQ-709 — dashboard tray
  Scenario: Failed saga appears in dashboard tray
    Given a saga fails and enters requires_operator mode
    When the operator opens the dashboard
    Then the Notifications tray shows the failed run
    And clicking it opens detail view with failed step + error + per-compensation outcome
    And the detail view offers "Mark resolved" + "Retry" buttons

  # REQ-715 — Matrix alert
  Scenario: requires_operator transition emits Matrix alert
    Given Matrix alert room is configured
    When a saga transitions to requires_operator=true
    Then a message is posted to the Matrix room
    And the message includes saga name + run ID + failed step + resolve URL

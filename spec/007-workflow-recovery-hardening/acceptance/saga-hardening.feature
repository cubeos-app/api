Feature: Workflow recovery hardening (spec/007)

  # Covers: REQ-700, REQ-701, REQ-702, REQ-703, REQ-704, REQ-705, REQ-706, REQ-711, REQ-712

  Scenario: Mid-workflow process kill triggers crash recovery on next boot
    Given a workflow is mid-step 5 of 9 and the api process is killed
    When api restarts
    Then crash-recovery detects the incomplete run
    And compensating actions for steps 1-4 run in reverse
    And the run is marked status=crashed

  Scenario: Per-step retry with exponential backoff
    Given a step with MaxRetries: 3 fails on first attempt
    When the runner retries
    Then attempts happen at 250ms, 500ms, 1s after each failure
    And audit log records each attempt

  Scenario: Compensation failing twice marks requires_operator
    Given step 3's Compensate fails twice consecutively
    When the runner gives up
    Then workflow_runs.requires_operator = true

  Scenario: Operator queries requires_operator runs
    When the operator GETs /api/v1/workflows?requires_operator=true
    Then the response includes all unresolved manual-cleanup runs

  Scenario: Operator marks resolved
    When the operator POSTs /api/v1/workflows/{id}/resolve with {notes:"cleaned up DNS manually"}
    Then the run's resolved_at is set + operator_notes recorded

  Scenario: requires_operator transition emits Matrix alert
    Given Matrix alert room is configured
    When a workflow transitions to requires_operator=true
    Then a message is posted to the Matrix room
    And the message includes workflow name + run ID + failed step + resolve URL

  Scenario: 6th concurrent workflow queues
    Given 5 workflows are running and CUBEOS_MAX_CONCURRENT_WORKFLOWS=5
    When a 6th submit arrives
    Then the submit queues
    And starts once one of the 5 finishes
    And if waited > 30s returns HTTP 503

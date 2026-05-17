Feature: FlowEngine saga runtime (spec/002 — retrospective)

  # REQ-200 + REQ-201
  Scenario: Saga runner executes steps in declared order
    Given a saga with 3 steps S1, S2, S3
    When the runner executes the saga
    Then S1.Execute runs first, then S2.Execute, then S3.Execute

  # REQ-202 + REQ-209
  Scenario: Failure mid-saga triggers reverse-order compensation
    Given a saga with 4 steps where S3 fails
    When the runner executes
    Then S1.Execute + S2.Execute ran
    And on S3 failure, S2.Compensate runs first, then S1.Compensate

  Scenario: Compensation failure continues rollback
    Given a saga where step 3 fails and step 2's Compensate also fails
    When rollback runs
    Then step 1's Compensate still runs
    And the secondary compensation failure is logged

  # REQ-203 + REQ-207 — progress
  Scenario: Per-step progress emits to subscribers
    Given a websocket client subscribed to /ws/flowengine/<run_id>
    When the saga runs
    Then the client receives an event per step with status started + completed (or failed)

  # REQ-204 + REQ-205 + REQ-206 — persistence
  Scenario: Run history persisted and queryable
    Given a saga has completed
    When the operator GETs /api/v1/flowengine/runs?saga_name=appstore_install
    Then the response includes the completed run with started_at, completed_at, status

  Scenario: Per-run detail returns step-by-step info
    When the operator GETs /api/v1/flowengine/runs/<id>
    Then the response includes per-step status + compensation_outcomes

  # REQ-210 — context cancellation
  Scenario: Cancelled context halts at step boundary
    Given a saga is mid-step 3 and the context is cancelled
    When the step completes (cancellation observed)
    Then compensation runs for steps 1 + 2

  # REQ-213 — name uniqueness
  Scenario: Two sagas with same Name() are rejected
    Given the engine has a saga named "test_saga" registered
    When code tries to register another saga also named "test_saga"
    Then Register returns ErrSagaNameDuplicate

  # REQ-215 — MockSaga
  Scenario: MockSaga lets handler tests run without full saga
    Given a handler test uses internal/flowengine/testing/MockSaga{Steps: [pass, pass, fail]}
    When the handler invokes the saga
    Then the mock simulates the failure path without invoking real Docker/HAL calls

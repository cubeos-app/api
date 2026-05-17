Feature: Orchestrator core (spec/001 — retrospective)

  # REQ-100 + REQ-101 + REQ-102
  Scenario: Handlers delegate to Orchestrator
    Given the AppsHandler.Install is invoked
    When the handler executes
    Then it calls Orchestrator.InstallApp
    And it does NOT call SwarmManager directly

  # REQ-103 + REQ-104 — per-stack serialization
  Scenario: Two concurrent installs to same stack serialize
    Given two install requests target stack "mystack" arriving 100ms apart
    When both are processed
    Then the second install acquires the per-stack mutex after the first releases it
    And both complete successfully (or both fail consistently)

  Scenario: Lock acquisition timeout returns HTTP 503
    Given stack "frozen-stack" has an install saga that hangs > 60 seconds
    When a second install on "frozen-stack" arrives
    Then the second request returns HTTP 503 within 60 seconds
    And the response body explains the lock timeout

  # REQ-106 + REQ-107 — saga delegation
  Scenario: Install delegates to appstore_install saga
    When Orchestrator.InstallApp is called
    Then flowengine.NewAppstoreInstallSaga is instantiated
    And flowEngine.Run is invoked with that saga

  # REQ-110 + REQ-111 — audit + error surfacing
  Scenario: Failed install records audit + surfaces compensation result
    Given the appstore_install saga fails at step 5 (proxy create)
    When the Orchestrator.InstallApp returns
    Then the error message includes "compensation:"
    And /cubeos/data/audit.log contains an orchestrator.install entry with success=false

  # REQ-112 — queue introspection
  Scenario: Queue endpoint shows pending + running requests
    Given 2 install sagas are running and 1 is pending
    When the operator GETs /api/v1/orchestrator/queue
    Then the response shows 2 entries under "running" and 1 under "pending"

  # REQ-113 — lint enforcement
  Scenario: Direct SwarmManager import outside managers/ fails CI
    Given a developer adds `managers.NewSwarmManager()` in internal/handlers/
    When `make lint` runs
    Then golangci-lint exits non-zero
    And the error message points at the forbidigo rule

  # REQ-115 — context cancellation
  Scenario: Cancelled context propagates to saga step
    Given Orchestrator.InstallApp is invoked with a context cancelled at the start of step 3
    When the saga executes
    Then step 3 observes ctx.Done() and returns ctx.Err()
    And compensating actions for steps 1 + 2 run cleanly

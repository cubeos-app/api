Feature: 12 Workflows + 14 Activities (spec/003 — RETROSPECTIVE)

  # Covers: REQ-300, REQ-301, REQ-304, REQ-305, REQ-306, REQ-307, REQ-309, REQ-310, REQ-311, REQ-312, REQ-313, REQ-315, REQ-316

  Scenario: 12 workflows present
    When inspecting internal/flowengine/workflows/
    Then exactly 12 *.go files (excluding tests) are present

  Scenario: 14 activities present
    When inspecting internal/flowengine/activities/
    Then exactly 14 *.go files (excluding tests) are present

  Scenario: No managers/compose.go file
    When inspecting internal/managers/
    Then no compose.go file exists
    And compose transformation logic lives in activities/appstore.go + app_install.go

  Scenario: Activities are idempotent
    Given activity "add_dns" with input {fqdn, ip}
    When the activity runs twice with the same input
    Then the end-state is the same (one DNS entry, not two)

  Scenario: Workflow failure triggers reverse-order compensation
    Given the appstore_install workflow fails at step 7 (proxy-add)
    When the failure occurs
    Then compensating actions for steps 1-6 run in reverse from step 6 backwards

  Scenario: Workflow persists to workflow_runs table
    When engine.Submit(ctx, SubmitParams{WorkflowType: "appstore_install"}) is called
    Then a row is inserted into workflow_runs with state=pending

  Scenario: Completion hook fires on terminal state
    Given OnCompletion("appstore_install", hook) is registered
    When the workflow reaches state=completed OR state=failed
    Then the hook fires asynchronously

  Scenario: appstore_install rejects unsupported compose features
    Given a compose file with `build: .` directive
    When appstore_install validates
    Then the workflow fails with HTTP 422 "Swarm requires pre-built images"

  Scenario: restore workflow verifies backup integrity
    Given a backup file with a corrupted SHA-256
    When the restore workflow runs
    Then verification fails before any state is restored

  Scenario: first_boot_setup is atomic
    Given the first_boot_setup workflow fails at step 8
    When the failure occurs
    Then /cubeos/data/.setup_complete is NOT written
    And the next boot retries from scratch

  Scenario: installed_apps table is NEVER written to
    When any workflow runs
    Then no INSERT INTO installed_apps statement is executed
    And only the unified apps table receives writes

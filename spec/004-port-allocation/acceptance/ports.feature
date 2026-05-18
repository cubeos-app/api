Feature: Port allocation with triple-source validation (spec/004 — RETROSPECTIVE)

  # Covers: REQ-400, REQ-401, REQ-402, REQ-403, REQ-404, REQ-405, REQ-406, REQ-407, REQ-408, REQ-409, REQ-410, REQ-411, REQ-412, REQ-413, REQ-414, REQ-415, REQ-416

  Scenario: PortManager type at the verified path
    When inspecting internal/managers/ports_new.go:91
    Then the PortManager struct has fields: db, swarm, hal, mu sync.RWMutex

  Scenario: Allocate returns lowest free port via triple-source
    Given DB has port 6100 allocated
    And Swarm publishes port 6101
    And HAL reports host process on port 6102
    When PortManager.AllocateUserPort is called
    Then the returned port is 6103 (lowest free per all 3 sources)

  Scenario: NewPortManager with nil swarm + nil hal falls back to DB-only
    When NewPortManager(db, nil, nil) is called
    Then PortManager construction succeeds
    And subsequent AllocateUserPort uses only DB validation

  Scenario: User app cannot request reserved port without system type
    Given app id=42 has type="user"
    When AllocatePort(42, 80, "tcp", ...) is called
    Then error "port 80 is reserved for system use" is returned

  Scenario: System app can claim reserved port
    Given app id=10 has type="system"
    When AllocatePort(10, 80, "tcp", "pihole http", true) is called
    Then the allocation succeeds

  Scenario: Pool exhaustion returns error
    Given all 900 user-app ports (6100-6999) are in use across DB+Swarm+HAL
    When AllocateUserPort is called
    Then ErrPortPoolExhausted is returned

  Scenario: Concurrency-safe via mutex
    When 100 goroutines call AllocateUserPort simultaneously
    Then no two goroutines receive the same port
    And the mutex serialises allocation

  Scenario: DeallocateAppPorts removes all rows for an app
    Given app id=42 has 3 port allocations
    When DeallocateAppPorts(42) is called
    Then `DELETE FROM port_allocations WHERE app_id=42` runs
    And subsequent SELECT returns 0 rows

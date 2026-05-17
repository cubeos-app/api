Feature: Port allocation (spec/004 — retrospective)

  Background:
    Given PortManager is initialised from SQLite at boot
    And the port pool is 6100-6999 (900 ports total)

  # REQ-400 + REQ-401 + REQ-411
  Scenario: User app cannot request port outside 6100-6999
    When the operator installs an app whose compose requests port 8080
    Then the install is rejected with HTTP 422
    And the error body explains the port-discipline rule (Article V)

  # REQ-403 — lowest-free allocation
  Scenario: Allocate returns lowest free port
    Given ports 6100, 6101, 6102 are in use; 6103 is free
    When PortManager.Allocate is called
    Then the returned port is 6103

  # REQ-404 + REQ-406 — release with persist
  Scenario: Released port becomes available + persisted
    Given port 6500 is allocated to app "uptime-kuma"
    When the operator uninstalls uptime-kuma
    Then port 6500 is released in-memory
    And SELECT port FROM apps WHERE id = '<uptime-kuma>' returns NULL

  # REQ-405 — pool exhaustion
  Scenario: All 900 ports in use returns 409 on next install
    Given the port pool is fully allocated
    When the operator installs another app
    Then the response is HTTP 409 with body explaining port-pool exhaustion

  # REQ-407 — boot-time map rebuild
  Scenario: API restart rebuilds map from SQLite
    Given 50 ports are allocated in SQLite
    When api process restarts
    Then on next /api/v1/system/ports call, 50 ports show as allocated

  # REQ-408 + REQ-413 — concurrency
  Scenario: 1000 concurrent allocators produce no duplicate ports
    Given 1000 goroutines call PortManager.Allocate simultaneously
    When all complete
    Then no two goroutines received the same port
    And ~900 succeed + ~100 fail with ErrPortPoolExhausted

  # REQ-409 + REQ-415 — endpoints
  Scenario: Operator queries port allocation map
    When the operator GETs /api/v1/system/ports
    Then the response is a map of port → app_id for all allocated ports

  Scenario: Operator queries free count
    When the operator GETs /api/v1/system/ports/free
    Then the response body is {"free_count": N} where N is the number of free ports

  # REQ-414 — duplicate handling
  Scenario: Duplicate port in SQLite goes to lower-ID app
    Given SQLite has app id=1 with port=6200 and app id=2 also with port=6200 (corruption)
    When PortManager initialises
    Then port 6200 is marked as allocated to app id=1
    And the audit log records the duplicate detection

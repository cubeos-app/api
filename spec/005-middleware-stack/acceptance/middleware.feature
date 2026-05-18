Feature: Middleware stack (spec/005 — RETROSPECTIVE)

  # Covers: REQ-500, REQ-501, REQ-502, REQ-503, REQ-504, REQ-505, REQ-506, REQ-507, REQ-508, REQ-509, REQ-510, REQ-511, REQ-512, REQ-513, REQ-514

  Scenario: Chain order is fixed
    When inspecting cmd/cubeos-api/main.go middleware registration
    Then the order is Logger → Recovery → RealIP → RequestID → CORS → Timeout(60s) → MaxBodySize(10MB) → SetupRequired → JWTAuth

  Scenario: /health bypasses JWTAuth
    When GET /health is called with no Authorization header
    Then HTTP 200 is returned

  Scenario: /api/v1/auth/login bypasses JWTAuth
    When POST /api/v1/auth/login is called with no Authorization header
    Then HTTP is NOT 401 (login proceeds)

  Scenario: SetupRequired blocks routes before first-boot
    Given /cubeos/data/.setup_complete is absent
    When GET /api/v1/apps is called
    Then HTTP 503 is returned with redirect to /api/v1/setup

  Scenario: SetupRequired allows /api/v1/setup/* during first-boot
    Given /cubeos/data/.setup_complete is absent
    When POST /api/v1/setup/wizard is called
    Then HTTP is NOT 503 (setup wizard proceeds)

  Scenario: Body over 10MB returns 413
    When POST /api/v1/apps with a 11MB body is called
    Then HTTP 413 is returned

  Scenario: Request over 60s returns 504
    Given a handler that sleeps 70s
    When the request is sent
    Then HTTP 504 is returned after ~60s

  Scenario: Panic recovered to HTTP 500
    Given a handler that panics
    When the panic occurs
    Then Recovery returns HTTP 500
    And Logger has captured the stack trace

  Scenario: Bad JWT returns 401
    When a request arrives with Authorization: Bearer invalid.jwt.here
    Then HTTP 401 is returned
    And fail2ban filter records the attempt

  Scenario: Valid JWT carries profile claim
    Given a JWT signed with the JWT_SECRET, claims sub=42, profile=advanced
    When JWTAuth verifies
    Then the request context carries the profile=advanced value

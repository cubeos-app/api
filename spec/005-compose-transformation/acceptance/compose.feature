Feature: Compose transformation (spec/005 — retrospective)

  # REQ-501
  Scenario: restart: always translated to deploy.restart_policy
    Given a compose file with `restart: always`
    When compose.Transform runs
    Then the output has `deploy.restart_policy.condition: any`
    And the legacy `restart:` key is removed

  # REQ-503 — depends_on long-form dropped
  Scenario: depends_on: service_healthy is dropped with warning
    Given a compose with depends_on of long-form service_healthy
    When transform runs
    Then the long-form condition is dropped
    And a warning is logged "depends_on condition not honored by Swarm"

  # REQ-505 — port out of range rejected
  Scenario: Port 8080 rejected
    Given a compose with `ports: ["8080:8080"]`
    When transform runs as a user app
    Then the response is HTTP 422
    And the body explains the 6100-6999 rule

  # REQ-506 — auto-allocate when no port declared
  Scenario: No port declared triggers auto-allocation
    Given a compose with no ports key but the app needs an HTTP port
    When transform runs
    Then PortManager.Allocate is called
    And the output ports entry uses the allocated port

  # REQ-508 — build directive rejected
  Scenario: build: directive rejected
    Given a compose containing `build: .`
    When transform runs
    Then the response is HTTP 422
    And the body explains "Swarm requires pre-built images"

  # REQ-509 — image pre-pull
  Scenario: Missing image triggers pre-pull
    Given a compose references `myorg/myapp:v1.0` not in local registry
    When the install saga's push_image step runs
    Then the image is pulled from source registry + pushed to localhost:5000
    And subsequent stack_deploy reads the image from localhost:5000

  # REQ-510 — labels applied
  Scenario: CubeOS labels applied to every transformed service
    When transform runs for app id="abc123"
    Then the output service has labels cubeos.app.id=abc123, cubeos.app.name=..., cubeos.app.version=...

  # REQ-511 — Swarm dry-run validation
  Scenario: Output validated by docker stack config
    When transform completes
    Then `docker stack config -c <output>` returns exit 0
    And any validation error from docker propagates back as a transform error

  # REQ-512 — privileged rejected for non-coreapps
  Scenario: privileged: true rejected for user app
    Given a user app compose has `privileged: true`
    When transform runs
    Then the response is HTTP 422
    And the body explains the constitutional violation

  # REQ-504 — host mode preserved for coreapps
  Scenario: pihole keeps network_mode: host
    Given coreapps/pihole/docker-compose.yml has network_mode: host
    When transform runs (as coreapp)
    Then network_mode: host is preserved unchanged

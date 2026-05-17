Feature: App-lifecycle sagas (spec/003 — retrospective)

  # REQ-300 — install saga shape
  Scenario: appstore_install runs all 9 steps in declared order
    Given a fresh device with profile=all_in_one
    When the operator installs uptime-kuma
    Then validate → allocate_port → write_compose → push_image → stack_deploy → add_dns → add_proxy → db_insert → emit_event run in order
    And the new app appears in `apps` table

  # REQ-306 — install rollback
  Scenario: install failure at step 7 (add_proxy) rolls back cleanly
    Given add_proxy will fail (NPM unreachable)
    When the operator installs uptime-kuma
    Then dns added in step 6 is removed
    And stack deployed in step 5 is removed
    And compose file deleted
    And port released
    And no apps row inserted

  # REQ-307 — profile gating
  Scenario: add_dns no-ops in standard profile
    Given active profile is "standard"
    When the operator installs uptime-kuma
    Then add_dns activity logs "skipping add_dns in profile=standard"
    And no DNS entry is created in Pi-hole

  # REQ-308 — image upload progress
  Scenario: push_image emits upload progress events
    When push_image step runs for a 500MB image
    Then progress events with image_upload_pct values appear (0 → 25 → 50 → 75 → 100)

  # REQ-309 — atomic .setup_complete
  Scenario: .setup_complete written atomically
    When the first_boot_setup saga reaches step "write .setup_complete"
    Then the file is written via .setup_complete.tmp + fsync + rename
    And a power cut during this step leaves the device in either pre-setup OR post-setup state (no half-state)

  # REQ-311 — uninstall is forward-only
  Scenario: appstore_remove partial failure logs partial state
    Given proxy_remove fails (NPM unreachable)
    When the operator uninstalls uptime-kuma
    Then proxy_remove step fails
    And the saga halts (does NOT roll back step 2 + 3)
    And /cubeos/data/audit.log records the partial state for operator cleanup

  # REQ-314 — network_mode_switch HAL failure
  Scenario: HAL failure during mode switch rolls back coreapp stops
    Given switching to wifi_router and HAL POST /network/mode fails
    When step 3 fails
    Then step 2's coreapp stops are undone (coreapps restart on previous mode)

  # REQ-315 — access_profile_switch + DHCP
  Scenario: Switching to all_in_one without managed iface skips DHCP enable
    Given operator switches to all_in_one but no managed iface designated
    When access_profile_switch saga runs
    Then the DHCP-enable step is skipped
    And the dashboard shows banner "designate managed interface to enable DHCP"

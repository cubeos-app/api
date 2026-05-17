# Requirements — App-lifecycle sagas (spec/003 — retrospective)

Source: `api/CLAUDE.md` §FlowEngine workflows + parent docs/spec/009-swarm-orchestrator.

> Retrospective for the 5 canonical sagas. ID convention: 300-block.

REQ-300: The system shall implement the `appstore_install` saga as 9 ordered steps: validate → allocate port → write compose → push image to local registry → stack deploy → add DNS → add proxy → DB insert → emit installed-event.
REQ-301: The system shall implement the `appstore_remove` saga as 6 steps: validate → stack remove → DNS remove → proxy remove → file cleanup → DB delete.
REQ-302: The system shall implement the `network_mode_switch` saga as 5 steps per parent docs/spec/008-network-modes design.
REQ-303: The system shall implement the `first_boot_setup` saga as 9 steps: collect SSH pubkey → collect network mode → collect access profile → swarm init → start infra layer → start platform layer → write .setup_complete → start full coreapp stack → emit boot-complete event.
REQ-304: The system shall implement the `access_profile_switch` saga as 8 steps per parent docs/spec/004-access-profiles design.
REQ-305: The system shall verify step idempotency for every saga in `internal/flowengine/<saga>_test.go`.
REQ-306: When the `appstore_install` saga fails, the saga shall execute compensating actions in reverse from the failed step.
REQ-307: When `add_dns`, `remove_dns`, `create_proxy`, `remove_proxy` activities run in profile=`standard`, the activity shall no-op and log the skip.
REQ-308: While the `appstore_install` saga is running step "push image to local registry", the saga shall report progress events with the image upload percentage.
REQ-309: When the `first_boot_setup` saga's step "write .setup_complete" runs, the saga shall write the file atomically (write to .setup_complete.tmp + fsync + rename).
REQ-310: The system shall maintain end-to-end tests under `tests/e2e/sagas/` that run each saga against a real Pi in QEMU.
REQ-311: If the `appstore_remove` saga fails partway, then the saga shall NOT attempt rollback (uninstall is forward-only) but shall log the partial state for operator cleanup.
REQ-312: When any saga step writes to the audit log, the saga shall include saga name + step name + step number + ctx.RequestID.
REQ-313: The system shall reject the addition of a saga step that does not declare both Execute and Compensate functions.
REQ-314: When the `network_mode_switch` saga's HAL call fails, the saga shall halt at the HAL step and run compensating actions for prior steps.
REQ-315: When the `access_profile_switch` saga changes the profile to `all_in_one`, the saga shall include the Pi-hole DHCP-enable step gated by managed-interface presence.

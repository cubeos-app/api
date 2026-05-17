# Design — App-lifecycle sagas (spec/003)

The 5 canonical sagas + their step graphs.

## appstore_install (9 steps)

```
1. validate          — req schema + app exists in store + dependencies satisfied
2. allocate_port     — PortManager.Allocate() → port in 6100-6999
3. write_compose     — render compose template with port + persist to /cubeos/data/apps/<id>/compose.yml
4. push_image        — docker push localhost:5000/<image>:<tag>
5. stack_deploy      — docker stack deploy -c compose.yml <stack-name>
6. add_dns           — HAL POST /pihole/dns/hosts <fqdn> → <ip>           [profile-gated]
7. add_proxy         — HAL POST /npm/proxy {fqdn, target}                  [profile-gated]
8. db_insert         — INSERT INTO apps (...)
9. emit_event        — audit log + websocket broadcast

Compensation (reverse from failure):
9'. (no-op)
8'. DELETE FROM apps WHERE id = ?
7'. HAL DELETE /npm/proxy/<id>
6'. HAL DELETE /pihole/dns/hosts/<fqdn>
5'. docker stack rm <stack-name>
4'. (no-op — image stays in registry; cleaned by GC)
3'. rm /cubeos/data/apps/<id>/compose.yml
2'. PortManager.Release(port)
1'. (no-op — validation pure-function)
```

## appstore_remove (6 steps)

```
1. validate          — app exists + not pinned
2. stack_remove      — docker stack rm
3. dns_remove        — HAL DELETE /pihole/dns/hosts/<fqdn>                 [profile-gated]
4. proxy_remove      — HAL DELETE /npm/proxy/<id>                           [profile-gated]
5. file_cleanup      — rm -rf /cubeos/data/apps/<id>/
6. db_delete         — DELETE FROM apps + PortManager.Release(port)

Compensation: NONE (REQ-311 — uninstall is forward-only).
Partial failure: log + leave operator to clean up.
```

## network_mode_switch (5 steps)

See parent `docs/spec/008-network-modes/design.md`. Per-step + per-compensation here:

```
1. validate target + hardware
2. compute diff (coreapps to stop / start)
3. HAL POST /network/mode {target} → HAL flushes firewall, swaps hostapd/wpa_supplicant config
4. restart affected coreapps in new order
5. persist + audit

Compensation: reverse, restoring prior mode.
```

## first_boot_setup (9 steps)

```
1. collect_ssh_pubkey   — from wizard form
2. collect_network_mode — from wizard form
3. collect_access_profile — from wizard form
4. docker swarm init --task-history-limit 1
5. start infra layer (pihole, npm, registry)
6. start platform layer (cubeos-api itself can't start itself — handled by cubeos-init.service)
7. atomic write of .setup_complete (REQ-309)
8. start full coreapp stack
9. emit boot-complete event

Compensation: reverse, restoring first-boot wizard state. (Operator can re-attempt wizard if step 7 fails.)
```

## access_profile_switch (8 steps)

See parent `docs/spec/004-access-profiles/design.md`. 8 steps with full reverse-compensation.

## Activity profile-gating (REQ-307)

```go
func (a *DNSActivity) Execute(ctx) error {
  profile := ctx.Value(profileKey).(string)
  if profile == "standard" {
    log.Info("skipping add_dns in profile=standard")
    return nil
  }
  return a.hal.AddDNS(ctx, ...)
}
```

Same shape for add_proxy / remove_dns / remove_proxy.

## End-to-end tests (REQ-310)

`tests/e2e/sagas/appstore_install_e2e_test.go` etc. — run against a real Pi via QEMU. Slow (~30 minutes); part of release-gate CI, not per-commit.

# Changelog — api

All notable changes to this project. Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) + [Conventional Commits](https://www.conventionalcommits.org/).

Generated from git history + tags by `scripts/sdd-generate-changelog.py` on 2026-05-18.


## [v0.2.0-beta.05] - 2026-03-01

### Added

- add GET /api/v1/setup/preconfiguration endpoint (0ccde67d)
- add dhcp_active field to network status response (476ca0a4)
- Bluetooth coexistence API with override persistence (da7fccbb)
- add WiFi AP whitelist/blacklist proxy endpoints (f4be1494)
- add reboot step to profile switch and access_url computation (94a907b5)
- Ethernet gate and AP teardown for Standard profile wizard (ff5896fa)

### Fixed

- self-healing Pi-hole auth when Swarm env var has stale password (eb840598)
- replace inline struct with named BluetoothOverrideRequest for swag (51640d35)
- DHCP reconciliation, verify steps, and infra error handling (38340039)


## [v0.2.0-beta.04] - 2026-02-28

### Added

- phase 3 — access_profile_switch FlowEngine workflow (e957790a)
- phase 2 — profile endpoints + test connectivity (904fc5a7)
- phase 1 — skip DNS/proxy steps for standard profile (d549795e)

### Fixed

- correct SBD text limit from 340 to 120 chars (655cb678)
- AP detection checks WiFi interfaces instead of HAL reachability (e586857f)
- NPM port 81, AP hardware detection, memory HAL fallback, schema v24 (8b65c183)
- uptime, memory, app status, and install URL for Tier 2 (33a49b24)
- port mode host + network mode from env (b7dc4774)


## [v0.2.0-beta.03] - 2026-02-27

### Fixed

- pass compose_path and domain to app removal workflow compensation (c22160af)
- ensure setup_complete flag on startup for existing deployments (b8bab3cb)
- create bind mount dirs before stack deploy; fix setup_complete flag (33f2a60b)
- inject X-HAL-Key on all API→HAL requests via transport wrapper (787e73d6)


## [v0.2.0-beta.02] - 2026-02-27

### Added

- send X-HAL-Key header for HAL ACL authentication [Phase 8.4] (c989d7dd)
- dynamic interface detection + mode availability (Phase 6c) (1108b7a3)
- Phase 6b — wifi_client mode with 30s fallback + FlowEngine workflow (ade39c63)
- Phase 6a — rename network mode constants to v2 names (7b0df3bd)

### Changed

- service dependency graph and config validation [Phase 8.1b] (24c88e59)
- dead code removal and stale TODO cleanup [Phase 8.1a] (78d969d9)


## [v0.2.0-beta.01] - 2026-02-24

### Added

- add bare-metal restore via USB detection and auto-restore (0f823a0c)
- add cron scheduler with retention policy and schedule CRUD API (8a0169c5)
- add destination adapters (USB/NFS/SMB) and AES-256-GCM encryption (379f4c92)
- add scope tiers, hot backup, FlowEngine workflows, and manifest verification (e8783962)
- add system_update workflow, activities, and API endpoints (685eb0c7)
- add UpdateManager with version check and manifest fetcher (3893f84a)
- add config_snapshots table and P0-seed config models (d9b4d971)
- add v18 migration — update_history, backup_schedules, enhanced backups (9296be30)
- offline-first batch 2 — auto-cache images to registry on appstore install (b01504e3)
- offline-first batch 1 — cached_manifests table, registry activities, cache workflow (6b8be566)
- registry-first batch 5 — background sync, GC, and update endpoint (af51dac9)
- replace inline first-boot setup with first_boot_setup saga workflow (dbd45a85)
- add /api/v1/metrics Prometheus endpoint (Batch 2.6) (dfcc33fa)
- add network mode switching workflow with saga rollback (a8cf5104)
- gut inline orchestration, replace with FlowEngine Submit calls, add workflow visibility API (e6d4fb41)
- wire FlowEngine into main.go with fat envelope, progress adapter, and adapters (f40f95e5)
- batch 2.5a gap closure - FQDN enrichment, bind mounts, volume storage, webui detection, subdomain prettification, completion hooks (e5e7c669)
- circuit breaker core + HAL + NPM integration (Batch 2.0a) (5ad3aece)

### Changed

- registry-first batch 4: API registry awareness + per-repo CI retag (f5e7aa98)
- gut inline orchestration, replace with FlowEngine Submit calls (ea325e89)
- update workflow tests for batch 2.5a (version 2, 15 steps) (00173735)
- P2-23 to P2-27: AppInstall/AppStoreInstall/AppStoreRemove workflows + real activities (af58f7fe)
- P2-17 to P2-22: saga orchestrator, workflow engine, AppRemoveWorkflow, HAL stubs (e2c551ca)
- P2-10 to P2-16: FlowEngine foundation (store, step executor, migration #16) (89becb4f)
- batch 2.0c: Pi-hole v6 REST API migration + circuit breaker (d06e6623)
- batch 2.0b: Docker/Swarm funnelTransport circuit breaker (78ffe9a7)
- P1-18: fix integration test credentials (use CI variable) (d0ec8886)
- P1-18: wire integration tests into CI (allow_failure: true) (81dc1f24)

### Fixed

- include encrypted .tar.gz.enc files in backup listing (d81f5733)
- registry-first deploy — service uses localhost:5000 image ref (89f362fa)
- make registry activity unmarshal errors non-fatal (B4) (6378b528)
- use localhost:5000 for docker push and fix PathEscape on image names (B2) (d50ce90b)
- WebSocket upgrade failing due to missing http.Hijacker on metrics statusWriter (a167ffbe)
- change StoreCachedManifestInput.Manifest to json.RawMessage (fixes unmarshal crash) (3f735ad6)
- three-tier system image protection (registry/appstore/cleanup) (21d32d63)
- protect system images from install/delete in registry (24df3385)
- gofmt registry.go + registry_sync.go (0c1bbf97)
- guard empty wifi password, safe defaults, skip bypasses workflow (45225138)
- guard configure_wifi against empty password, safe default in GenerateDefaultConfig (ed757085)
- align insert_app activity with actual apps table schema (58efbb2a)
- forward step output piping, SSE timeout exemption, bind mount pre-creation (e34bae88)
- pass forward step output as compensation input, increase convergence timeout (6f8db15c)


## [v0.2.0-alpha.01] - 2026-02-22

### Added

- replace FileBrowser API sync with Dufs compose+redeploy pattern (a8489265)
- sync admin password to File Browser on change and first boot (1dd4db56)

### Changed

- sync password retry files (pihole, npm, filebrowser) (c8b3f5f7)
- alpha.26 batch 3: B1 HAL status fix, B3 app store auto-sync on mode change (3e8eb068)
- alpha.26 batch 2: B9 duplicate 409, B10 docker/disk alias, B8 upstream fallback (1a36e6c2)
- alpha.26 batch 1: B4 open-app URL, B5 container logs, B6 health check, B7 display names (2ae4e071)

### Fixed

- B126 netplan-first WiFi connect flow (3fb6d983)
- pihole uses compose recreate (not restart), NPM uses /auth endpoint for password changes (1bb85b03)
- Pi-hole uses env var+restart (setpassword blocked by FTLCONF), NPM is_disabled as int (7ed49cb2)
- wire Pi-hole and NPM password sync into startup and password change flows (58db3673)
- NPM bootstrap handles default credentials, Pi-hole uses docker exec for Balloon-SHA256 (76aa5748)
- FileBrowser password sync retry with backoff + startup resync (dea5cf77)
- filter ghost apps with empty name from installed list (804ac118)
- B4a kiwix, X1 filebrowser, B6 terminal in seeds; B5 PruneOrphanApps; fix docsindex port 6050→6032 (1bd48696)


## [v0.1.0-alpha.25] - 2026-02-21

### Added

- unified install parity — port/volume/subdomain overrides for registry apps (e3585004)
- unified install endpoint - route registry installs through Orchestrator with async job tracking (5602b5f8)
- online_tether network mode — AP + NAT via Android USB tethering (fbf682ef)
- online_tether network mode — AP + NAT via Android USB tethering (5737dafa)

### Changed

- Batch 3: remove legacy AppStoreManager.InstallFromRegistry() (bee6de16)
- B115,B116,B118,T1.5: fix ListApps null relations, DNS reload, NAT field mismatch, schema_migrations (89e06d39)

### Fixed

- share NPM and Pihole managers with Orchestrator (46fcc04d)
- retry NPM requests on 500 with backoff (448b5120)
- make DNS and NPM proxy fatal during install with full rollback (4a6db68b)
- clean stale FQDN + NPM proxy before registry install (30c21593)
- context canceled on registry install — use Background() for async goroutine (dbd5e920)
- add managers/network.go with online_tether SetMode dispatch (8071069c)
- B92b OFFLINE netplan template gives eth0 same IP as wlan0 (b81fd4a8)


## [v0.1.0-alpha.24] - 2026-02-20

### Changed

- FQDN insert uses ON CONFLICT DO UPDATE instead of DO NOTHING (51425d50)
- fix FQDN collision overwrite + prettify registry app titles (52b283c2)
- registry deploy uses full app pipeline (125d3ae9)
- Registry deploy uses PortManager triple-source port allocation (95a46889)
- Fix MeshtasticNode struct — last_heard is int64, not string (d027bc24)
- alpha.24 batch 4: B102 registry deploy endpoint (0a69e83c)
- alpha.24 batch 2: B94 network desync, B95 meshtastic types, B99 swarm names, B100 default store (a436f84d)


## [v0.1.0-alpha.23] - 2026-02-19

### Added

- migrate deploy to SSH from GPU VM (no Pi runner needed) (b6ed524a)

### Changed

- repo cleanup (f4b1c227)

### Fixed

- B83 HALError status forwarding, B88 netplan DHCP mode switch (5f55eea0)


## [v0.1.0-alpha.22] - 2026-02-19

### Added

- Batch 2 — Pi-hole DHCP + netplan + WiFi detection (16cd25b6)

### Changed

- T11-T13: static IP support — schema, models, API, netplan generation (e8ff5d2b)


## [v0.1.0-alpha.21] - 2026-02-18

### Fixed

- B60 GPS port path→query param (9ef103ba)
- FR01 WiFi country default US→NL (d4ce5489)


## [v0.1.0-alpha.20] - 2026-02-17

### Added

- Batch 2 — API bridge layer for user-confirmed UPS selection (698b6f31)

### Fixed

- enable WebSocket for cubeos.cube proxy (B58) (686eea6f)
- DHCP on eth0 + persist WiFi password (B52) (fe2d21fd)
- batch 3 HAL client GPS double encoding (B50) (fff1fff9)
- batch 1 API critical fixes (B59, B48, B38/54/55, B57) (f1419c8c)


## [v0.1.0-alpha.19] - 2026-02-17

### Added

- CheckImage endpoint, registry-aware install flow, fix terminal port, add kiwix proxy (6383aff2)

### Changed

- increase health timeout to 120s for ARM64 startup (401de4ef)
- robust host-mode Swarm deployment (no --detach=false) (1ba036ae)
- B38+B39+Errors: Fix all 3 logs page bugs (5c6a5bd7)
- Use writeHALError for all hardware GET endpoints (9a254278)

### Fixed

- Fix deploy: portable grep (no -oP), sudo ss, || true guards (46345383)
- B45 built-in fallback when /cubeos/docs/ is empty (13a45c01)


## [v0.1.0-alpha.18] - 2026-02-16

### Changed

- alpha.18 batch 3: B26 seed ports, B28 seed FQDNs, B25 timezone host-root, B20 cache system stats, B21 container logs nil guards, B22 HAL log normalization, B24 bundle error handling (370e168f)


## [v0.1.0-alpha.17] - 2026-02-16

### Fixed

- GPIO handler returns empty list instead of 500 (3e7b0a11)


## [v0.1.0-alpha.16] - 2026-02-16

### Changed

- alpha.16: B01 optional env vars, B02 CUBEOS_VERSION, B04 swap/ZRAM, B06 swagger URL (97800ce6)


## [v0.1.0-alpha.15] - 2026-02-16

### Added

- seed NPM core proxy rules on API startup for out-of-box experience (de0cffd3)
- accept OpenVPN credentials, write auth file (33f2fb4f)
- use HAL WiFi status for rich connection data (4d071f57)
- Wire PortManager into AppStoreManager — complete port unification (282ce756)
- Triple-source port validation (DB + Swarm + Host) (f8d9ffb5)
- Add GetListeningPorts method for triple-source port validation (14dca97c)
- Session 6 — LayoutLocked field for dashboard lock toggle (b7ad51b0)
- add widget_dimensions field to DashboardLayoutConfig (60a6a2c8)
- add DashboardConfig to preferences model + merge-update in manager (9cf748cf)
- auto-detect browser vs API click behavior + host-root browse fix (06d816a2)
- volume mount management — Sprint A backend (b1f7c50a)
- async install/uninstall with SSE progress tracking (217509fc)
- prettify app FQDN subdomains (strip store prefixes like big-bear-) (9468a177)
- auto-reconcile orphaned installed app records (startup + runtime) (f59dd746)
- comprehensive CasaOS-to-Swarm manifest sanitizer (25+ directives) (7a99b638)
- add default_credentials flag to /system/info (cafcfdd1)
- rewrite Iridium handlers + SSE proxy pattern (Session 2/4) (4418fc98)
- overhaul client for HAL hardening integration (3bfdff69)
- implement 6 missing API endpoints (Sprint 4 Group A) (597b4caa)
- complete Swagger annotations for all API endpoints (708 annotations) (1febbd1e)
- Add Swagger UI auto-generation via swaggo (a344aa3c)
- Add 100 HAL endpoints with swaggo annotations (Sprint 6) (10f5214a)
- Complete HAL client with all 80+ endpoints (faf7c184)
- integrate NPMManager with service account authentication (fa053d92)
- integrate Network Modes V2 (b115d68d)
- add network extended and firewall endpoints (f6f692ed)
- add CasaOS import API (0876a887)
- implement NPM integration endpoints (Sprint 4E) (ae59a953)
- implement Sprint 4B/4C API handlers (ports, fqdns, registry) (61c1e263)
- add JWT authentication to integration tests (v3.0) (a9589735)
- add OpenAPI spec and integration tests (S3-21, S3-22) (f5ddeace)
- add GetAPClients client method (876cb513)
- add OpenAPI 3.0 spec and integration tests (S3-21, S3-22) (f58023d5)
- add HAL client for hardware abstraction layer (5cd76745)
- add database migrations for Sprint 2/3 schema (b17e4280)
- add SwarmManager for Docker Swarm orchestration (Sprint 1) (341963d2)
- fail-fast configuration with centralized env loading (090c49e0)
- Add NPM/Pi-hole/Compose integrations to AppManager (330cb05b)
- Add AppManager handlers and models (6f2eb9f7)
- Add AppManager for app/port/domain/profile management (2a105aa7)
- Add AppManager for app/port/domain/profile management (373d6ff5)
- add offline docs API + local RAG source links (08fe31f8)
- GitHub URLs for sources, reduce context for conciseness (47517c3a)
- add RAG support - queries ChromaDB for documentation context (920eb22d)
- add AI chat endpoint for Ask CubeOS (b093572f)
- CubeOS API v12 - full sync from device (5b1000bc)
- Add JWT authentication system (Sprint 1.3) (343f1496)
- Add Docker deployment files (5b3147ad)
- Add Docker container management endpoints (a8795f09)
- Add /api/v1/system/info and /api/v1/system/stats endpoints (bc5914b8)

### Changed

- Alpha.15: remove all nsenter from API, route host ops through HAL, relative Swagger URL (2addd755)
- alpha.14: B58 AP live-apply, B56 NPM type fix, B39 HAL fallback, B38 ZRAM detection (196f37fd)
- alpha.12: fix journal paths, NPM retry, proxy rules, HAL error handling (B42, NPM-1/2/3, B41) (6ac3e4c5)
- alpha.10: add version to system/info, fix host IPs, wire wizard apply, sync Swarm apps (B16, B23, B17, B21, B22, B18) (a9eb64b8)
- alpha.9: proxy reboot/shutdown to HAL + device model fallback (B6-B, B3) (83df0bae)
- Session 10: Add visibility fields, widget_refresh_intervals, user_presets to dashboard config (de5688e8)
- wallpaper endpoints, Tor/VPN routing, services deprecation (c3a3039c)
- Remove stale Sprint 1.1 TODO from system.go (7c418618)
- redeploy API with loadAppRelations fix (93ac96f1)
- zerolog migration complete (94 calls), N1 RLock fix, verify-routes CI (402b2070)
- zerolog migration batch 1 — 74/95 calls across 4 files (859b1bc6)
- add handler test suites with validation and route registration tests (2083b96b)
- Session 2: Migrate installed_apps to unified apps table (d06a0d23)
- Session 1: Dead code purge + DI cleanup (b1f8f5aa)
- Session 4: Power monitor, support bundle, HAL firewall status, Android route alias (1420ec90)
- Session 3: Meshtastic handler rewrite - 12 lifecycle routes, SSE proxy (ddafd640)
- coverage expansion - docker, determineHealth, auth, port deadlock, FQDN integration tests (2f7f8cf3)
- fix broken tests - unused imports, duplicate symbols, access_token field, goroutine safety, schema parity (4de882bc)
- FS-08G02: global polish — structured logging, rows.Err(), hardcoded IPs, graceful shutdown (3c10f95f)
- FS-07G02: wire BackupsHandler to BackupManager, fix VPN validation & registry URL-escaping (0237101b)
- FS-07-G01: storage/mount consolidation, SMB wiring, input validation (f2d864d1)
- route all firewall ops through manager, implement save/restore/reset, add input validation (03b6d010)
- CasaOS orchestrator routing, CommandContext, apps 503 fallback, GetApp error handling (149b302b)
- FS-05G01: AppStore install flow — Swarm deploy, NPM/DNS wiring, path fixes, JSON injection fixes (1c368784)
- FS04-G02: Fix DNS config, SetStaticIP gateway, AP config persistence, context propagation (d9bc1aa4)
- Wire FQDN→NPM→Pi-hole pipeline (a33f9be5)
- gofmt managers/network.go after type dedup (fc0d0991)
- Auth hardening, CORS lockdown, setup protection (778b81fc)
- FS-01-G02: Schema consolidation — single source of truth (6ae9d3e5)
- FS-01-G01: Dead code purge — remove 974 lines, 35 duplicate Swagger routes (d718f467)
- remove debug logging from orchestrator (650f5b00)
- more granular timing to find blocking point (4a3d188b)
- add timing logs to ListApps and getAppStatus (9f6d92cc)
- Sprint 3: Complete VPN, Mounts managers + OpenAPI + Integration tests (6a78c607)
- Sprint 3: Wire network handler endpoints (5714918c)
- Sprint 3: Unified Apps API, Profiles API, Network Mode Switching (b9a4bdd4)
- Complete S2-16 and S2-17: ComposeTransformer + comprehensive tests (67895baf)
- Increase deploy health check timeout for Swarm scheduling (c81b6e8d)
- Temporarily disable AppManager in main.go (Sprint 3 will integrate Orchestrator) (f906bf32)
- Restore Alert and StatsSnapshot types (08148702)
- Sprint 2: Add Orchestrator, unified schema, and new models (63ddc7c3)
- Sprint 0: Remove MuleCube references from API code (6aa948be)
- gofmt appmanager.go and ports.go (d534974b)
- trigger rebuild for NPM URL fix deployment (e083b52d)
- gofmt appmanager files (69a1c99f)
- trigger rebuild (f7fb8a95)
- Format Go files with gofmt (ba8da7d8)
- format chat.go (8517e194)
- format chat.go (32ef4e78)
- optimize AI prompt for Qwen 0.5B (research-based) (4283b84e)
- format chat.go with gofmt (59957939)
- use multiarch runner on gpu01 for multi-arch builds (77782ce0)
- use multiarch runner for multi-arch builds (ef0f1bb8)
- multi-arch Docker image + fix gofmt (41e219d2)
- multi-arch Docker image (amd64 + arm64) (b8a09fe4)
- add unit tests for handlers and config packages (89b5f2b5)
- go mod tidy (20f12b7e)
- use pre-built builder image for faster pipelines (8fbac06c)
- upgrade to Go 1.24 (5eded48c)
- push Docker images to ghcr.io/cubeos-app/api (3f5f43e3)
- add Go module caching for faster CI/CD (f5960b32)
- enable auto-deploy on main branch (ad9f75b8)
- format code with go fmt (3eb77fb1)
- add GitLab CI/CD pipeline (38ed105e)
- Initial commit: CubeOS API skeleton (c3e0a7ad)

### Fixed

- B51 boot log fallback, B44 host hostname, B45 swagger whitelist+host, B48 already fixed (004ac570)
- country code persistence, pprof endpoint, gitignore binary (e1386145)
- NPM bootstrap env var mismatch (9eed5b4e)
- parse remote_path into server+share for HAL, use /mnt/ for local path (63fa4d41)
- proxy public IP check through HAL for correct VPN exit IP (133c29df)
- sanitize config names for Linux interface compatibility (ec8f4ffa)
- use dynamic interface detection for WiFi status, saved networks, and disconnect (21399841)
- add DHCP request to setOnlineWiFiMode after WiFi connect (78f16250)
- auto-detect USB WiFi dongle, remove hardcoded interface name (b6f8be88)
- normalize rules with ports/interfaces, pass internet RTT (941830c0)
- FirewallStatusResponse JSON tags match HAL response (1bb825ee)
- NAT status wrong HAL endpoint, IP forward error handling, DHCP lease paths (304d0e49)
- firewall user_only filter + rule normalization, traffic stats array format (5201dae6)
- correct file paths for API container mounts and HAL unblock endpoint (11b4eeed)
- Update TestPortManagerGapFinding for gap-first allocation (8d6b22fb)
- add grid_layout, widget_opacity, advanced_section_order to DashboardLayoutConfig (a10847b5)
- align DashboardConfig schema with plan — per-mode DashboardLayoutConfig with all 20 fields (30378bc4)
- move swagger UI from /docs/* to /swagger/* to resolve routing conflict with docs handler (129397be)
- DNS cleanup uses prettified subdomain fallback (b326a879)
- add missing npm_proxy_id column + log FQDN insert errors (f594f2a1)
- load fqdns/ports in ListApps so frontend can build URLs (c667ae5b)
- browse host filesystem via host-root mount (0aadcc04)
- register GET /system/browse route for directory browser (c18f13fc)
- add nil guards for manager in async handlers (412955f9)
- status desync for store-installed apps (bebbaeb1)
- clean up app directories on uninstall (b3bc4ef4)
- Pi-hole v6 DNS path (hosts/custom.list) and reload command (reloaddns) (b22278dd)
- clear catalog Installed flag during runtime orphan reconciliation (d5f731bd)
- create bind mount dirs as 0777 for non-root containers (8bf01511)
- pre-create bind mount dirs before stack deploy (Swarm doesn't auto-create) (e71a9f65)
- replace hardcoded /DATA/AppData/{appname} paths in CasaOS manifests (dd495f13)
- remap CasaOS manifest ports to allocated 6100+ range (4106d237)
- strip root-level name and x-casaos extensions for Swarm compatibility (89c95a91)
- restore ManifestPath from DB in loadCatalog + sanitize manifests for Swarm (3b66778c)
- sanitize CasaOS manifests for Swarm compatibility (depends_on, container_name, privileged) (0c829ffd)
- catalog persistence, BT status codes, client blocking (BUG-07,08,10) (6ac6409c)
- support query param token for browser file downloads (support bundle, backups) (bbe3a1a4)
- use PRETTY_NAME for OS display instead of bare NAME (BUG-04) (021caddb)
- route hostname and OS info through HAL (BUG-04) (5be63631)
- route hostname through HAL instead of direct file read (BUG-04) (f43f99c6)
- wire NPMManager into AppStoreManager, remove duplicate NPM auth with hardcoded creds (-215 lines) (851845ca)
- rewrite verify-routes (func-based), remove dead GetWSConnections, CI bash (44c84d6b)
- install bash+grep in verify-routes CI job (Alpine) (6513748f)
- session1 audit — PUT charging/preferences routes, remove dead annotations, add zerolog warnings (3f7fe0c6)
- UpdateFQDN NPM proxy sync + unify error helpers (18b68a78)
- replace scale-down/up deploy with atomic stop-first update (aeb78825)
- add sudo for iptables/systemctl in deploy pre-flight (ab0aa5f6)
- prevent iptables chain corruption in deploy stage (2c9b2bd6)
- PathEscape all path params, fix DefaultHALURL, remove duplicate GetFirewallRules, implement GetTrafficHistory, fix media stream URL (331d82ee)
- FS06G03 annotation cleanup - charging method, health path (cfb405de)
- system manager & monitoring fixes (f14c868e)
- gofmt formatting on fqdns.go (2566906f)
- deduplicate types between models and managers packages (4523c452)
- swarm, docker & port allocation fixes (3eedc365)
- FS-03G01 — critical orchestrator fixes (9a9ff477)
- main.go cleanup & manager wiring (25249686)
- Fix storage health: return HAL error instead of falling through to local smartctl (2e78fe95)
- Fix HAL response parsing - correct types for firewall/traffic (e91beed6)
- Fix API audit 500 errors - proxy hardware ops to HAL (f6de5823)
- remove /api/v1/ prefix from swagger annotations (19eecf38)
- Use NPMManager for proxy-hosts endpoint - fixes token auth (fb1b79f7)
- Bulletproof deploy for host-mode Swarm with scale-down strategy (89860abd)
- Wire missing routes for temperature, storage health, and fix icon error format (b5217406)
- Add --update-order stop-first for host-mode port updates (7417228d)
- Add missing os import for HAL_URL env var (5c2a23d7)
- Read HAL_URL from environment instead of hardcoding (98f97d27)
- Add missing route handlers and fix path mismatches (f8db6c3e)
- Add /hal prefix to HAL client base URL (fd5725de)
- Correct @Router paths to match actual mount points (27928a7f)
- use NetworkHandler.Routes() - enables all 30 network endpoints (1988e9be)
- force image update on deploy - no more stale images (d73597e6)
- register all 9 missing routes, fix swagger /api/v1 prefix (32a5df45)
- add blank models import to vpn.go for Swagger type resolution (fdb77caa)
- correct Swagger annotation type names (45ef2d8c)
- replace models.AppConfig with map[string]interface{} (b4891ae1)
- correct CatalogApp to StoreApp in Swagger annotation (f5fae827)
- format auth/handlers.go (e4318b15)
- Add ErrorResponse type for swaggo compatibility (2af49209)
- register Network V2 routes in main.go (b596cc03)
- mount portsHandler + use FirewallHandler (Sprint 5C) (73310497)
- persist network mode to database across restarts (6fc88b77)
- gofmt casaos.go (61704be8)
- NPM enabled field handles bool/int from API (07e6ff5f)
- use gateway IP (10.42.24.1:5000) for registry handler (610593e3)
- add helper functions to fqdns handler (dca1d6f7)
- remove npm_proxy_id from fqdns query (column doesn't exist) (3bdddb9b)
- return 404 instead of 500 for non-existent resources (35dbb1c1)
- standardize API error responses with error field (b9ab5d9b)
- remove duplicate /network mount, add /ap/clients route (5ce65f08)
- mount NetworkHandler routes for /api/v1/network endpoints (19ae4483)
- wire MountsManager DB, implement GetPublicIP (cf09338f)
- increase stack drain wait to 20s for Swarm timing (612358f0)
- gofmt integration test file (452b20dc)
- resolve all HAL integration compilation errors (e5d0efcd)
- use nsenter for WiFi interface access from container with pid:host (fcc268a4)
- add ClientInterfaces field to NetworkStatus model (913bab18)
- network manager - fix struct fields + add missing handler methods (fc353a9e)
- SQLite deadlock in ListProfiles - close rows before loading apps (af934ca3)
- add migration 8 for is_primary column in port_allocations (fb92d062)
- detect compose container status correctly (running not up) (ee89a485)
- gofmt orchestrator.go (ac51e973)
- add 5s timeout to GetServiceStatus to prevent /api/v1/apps hanging (eabf3c49)
- call MigrateAndSeed to run database migrations (63607287)
- gofmt migrations.go (26f1b48b)
- gofmt vpn handler (3de12fb5)
- remove unused networkHandler variable (a9447f23)
- remove duplicate /network route mount (23780c3a)
- Fix deploy: use Swarm stack instead of docker compose (6209acbb)
- Fix TestPortManagerWithDB: insert allocation between calls (9ca78c0b)
- gofmt swarm.go (2a5a7a20)
- use container.LogsOptions for Docker SDK compatibility (b47237df)
- add docker rm before compose up to prevent name conflicts (84c1ecd9)
- format logs.go with gofmt (2a334d9f)
- syntax errors in setup.go and ports.go from MuleCube cleanup (bbb21525)
- add --no-cache to prevent buildx caching stale binaries (b02836ad)
- restore build stage with cache-busting, update ports to 6010 (9f4f2f61)
- replace go-sqlite3 with empty stub for CGO-free builds (54c08929)
- update health check port to 6010 (0c014613)
- update deploy path to separated cubeos-api compose (ddc9ceaf)
- remove orphaned error check and unused import (554c9469)
- use database.Open() for pure-Go SQLite driver (03ed3c38)
- update config tests for fail-fast behavior (ee562d01)
- gofmt formatting (d3b03835)
- add godotenv to go.sum (b9bbeb19)
- proper app status, comprehensive port detection, container name mapping (0bb34699)
- appmanager round 2 - force compose_path, docker inspect ports, FQDN port fallback (33a73cff)
- appmanager bugs - status display, compose_path, ports scanning (2c29624b)
- use docker inspect for status, fix NPM type, use /cubeos paths (9eac4005)
- use /cubeos base path for ComposeManager and PiholeManager (45d1d9b4)
- correct NPM API URL from 127.0.0.1:81 to 192.168.42.1:6000 (12f02ee9)
- use correct NPMProxyHostExtended type (7cd4ed3d)
- auto-discover compose paths and sync ports from docker ps (eeb04e49)
- use correct NPMProxyHostExtended type (6f54dffc)
- correct ports.go with proper docker ps scanning functions (1ef768cb)
- add missing closing brace in SyncFromSystem (b129072b)
- improve domain sync and add docker ps port scanning (5c8db389)
- remove unsupported expiry field from NPM token request (d1fb81d8)
- use correct NPM URL in status response (ec77a7c4)
- correct paths for PiholeManager and NPM API URL (60921711)
- use correct base path for ComposeManager (/cubeos not /cubeos/data) (0018550c)
- resolve type redeclaration errors in appmanager integration (f3823c29)
- read Ollama/ChromaDB config from environment variables (071862ea)
- format main.go (88f2e640)
- switch to pure Go SQLite driver (no CGO) (1fc4806a)
- correct compose file path and service name (b7078e72)
- use shell executor for package stage (ARM64) (1c3e7687)
- use QEMU for multi-arch buildx (79403b70)
- disable TLS for buildx in DinD (287c4b7f)
- use unique buildx builder per job (0e761c02)
- use pre-built binary in Docker image (skip redundant Go build) (c9e003ca)
- disable caching to avoid permission issues (4991c6db)
- exclude .go-cache from gofmt check (d7c62955)
- pin Go version to 1.22 to avoid toolchain upgrade issues (474be3cb)
- update gitignore to not exclude cmd directory (db2f070f)
- remove old code with incorrect imports, clean up module (3334d3c0)
- run as root for Docker socket access (63620038)
- Fix Makefile duplicate build target (df7c7b4b)

### Removed

- Remove AppManager references (replaced by Orchestrator in Sprint 3) (fb52c173)
- Remove duplicate ApplyProfile types from models.go (3df5ea9f)
- Remove deprecated files replaced by Sprint 2 (d563d53a)

### Security

- FS-02G01 path traversal, SSRF, body limits, JSON injection (6eee4c18)


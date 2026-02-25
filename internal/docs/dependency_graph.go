// Package docs contains architecture documentation for the CubeOS API.
//
// # Service Dependency Graph
//
// This file documents the initialization order and dependency DAG for all
// managers and handlers created in cmd/cubeos-api/main.go.
//
// ## Initialization Phases
//
// The API starts in 7 sequential phases. Each phase depends only on prior phases.
//
//	Phase 1 — Configuration & Database
//	  config.Load()         → reads /cubeos/config/defaults.env, secrets.env
//	  config.Validate()     → validates all config fields at startup
//	  database.Open()       → opens SQLite (pure-Go, no CGO)
//	  database.InitSchema() → creates tables (fatal on failure)
//	  database.Migrate()    → runs migrations (non-fatal on failure)
//	  seedDefaultAdmin()    → ensures admin user exists
//
//	Phase 2 — Core Infrastructure Managers
//	  circuitbreaker.New("docker")  → shared circuit breaker for Docker daemon
//	  DockerManager(cfg, dockerCB)  → Docker container management (optional, nil if Docker unavailable)
//	  hal.NewClient(HAL_URL)        → HAL client for all hardware operations
//	  SystemManager(halClient)      → system info, stats, temperature
//	  NetworkManager(cfg, halClient, db) → network modes, WiFi, AP, DHCP
//
//	Phase 3 — Extended Managers (no cross-dependencies within phase)
//	  LogManager()                         → journal/container log access
//	  FirewallManager(cfg, halClient)      → firewall rules via HAL
//	  BackupManager()                      → backup/restore (.SetDB later)
//	  ProcessManager()                     → host process management
//	  MonitoringManager(systemMgr, networkMgr) → system monitoring + alerts
//	  PreferencesManager()                 → user preferences
//	  WizardManager(cfg, docker)           → setup wizard profiles
//	  PowerManager()                       → UPS/battery status
//	  StorageManager()                     → SMB shares, disk health
//
//	Phase 4 — App Ecosystem Managers
//	  DatabaseManager(db.DB)               → generic DB operations for apps
//	  PiholeManager(cfg)                   → Pi-hole v6 REST API (DNS management)
//	  NPMManager(cfg, configPath)          → Nginx Proxy Manager API (proxy hosts)
//	  SwarmManager(dockerCB)               → Docker Swarm service management
//	  PortManager(db.DB, swarmMgr, halClient) → triple-source port allocation
//	  AppStoreManager(cfg, dbMgr, dataDir, piholeMgr, npmMgr, portMgr) → app catalog
//	  Orchestrator(db, cfg, halClient, dockerCB, swarmMgr, npmMgr, piholeMgr, registryURL) → app lifecycle
//	  SetupManager(cfg, db, halClient, fbClient, piholePwClient, npmMgr) → first-boot wizard
//	  UpdateManager(db.DB)                 → background update checks
//	  VPNManager(cfg, halClient)           → WireGuard/OpenVPN/Tor
//	  MountsManager(cfg, halClient)        → SMB/NFS mounts (.SetDB later)
//	  RegistrySyncManager(db.DB, registryURL) → background registry sync
//
//	Phase 5 — FlowEngine (Workflow Orchestration)
//	  WorkflowStore(db.DB)     → persistent workflow state
//	  ActivityRegistry()       → activity function registry
//	  Register activities:
//	    DockerActivities(swarmMgr)
//	    InfraActivities(piholeMgr adapter, npmMgr adapter)
//	    DatabaseActivities(db.DB, portMgr)
//	    HALActivities(halClient)
//	    AppInstallActivities(orchestrator adapter)
//	    AppStoreActivities(appStoreMgr adapter, orchestrator adapter)
//	    AppRemoveActivities(db.DB)
//	    NetworkActivities(networkMgr, halClient)
//	    WifiClientActivities(networkMgr, halClient)
//	    SetupActivities(setupMgr)
//	    RegistryActivities(db.DB)
//	    UpdateActivities(db.DB, swarmMgr adapter, updateMgr)
//	    BackupActivities(db.DB, backupMgr adapter, swarmMgr, destRegistry adapter, encryptor adapter)
//	  WorkflowEngine(store, registry, config) → core engine
//	  Register workflow definitions (10 workflows)
//	  engine.Start() → fatal if fails
//	  Wire engine into managers:
//	    orchestrator.SetFlowEngine(engine, store)
//	    appStoreMgr.SetFlowEngine(engine, store)
//	    networkMgr.SetFlowEngine(engine, store)
//	    setupMgr.SetFlowEngine(engine, store)
//	    backupMgr.SetFlowEngine(engine, store)
//
//	Phase 6 — HTTP Handlers
//	  Handlers(cfg, db, docker, halClient, systemMgr, networkMgr, fbClient, piholePwClient, npmMgr)
//	  ExtendedHandlers(logMgr, firewallMgr, backupMgr, processMgr, wizardMgr, monitoringMgr, prefMgr, powerMgr, storageMgr, halClient)
//	  AppStoreHandler(appStoreMgr, npmMgr)
//	  SetupHandler(setupMgr, flowEngine, feStore)
//	  ChatHandler(cfg)
//	  DocsHandler()
//	  AppsHandler(orchestrator)
//	  ProfilesHandler(orchestrator)
//	  WorkflowsHandler(feStore)
//	  NetworkHandler(networkMgr, halClient)
//	  FirewallHandler(firewallMgr, halClient)
//	  VPNHandler(vpnMgr)
//	  MountsHandler(mountsMgr)
//	  PortsHandler(portMgr)
//	  FQDNsHandler(db.DB, npmMgr, piholeMgr)
//	  RegistryHandler(registryURL, registryPath, portMgr, orchestrator, db.DB, syncMgr, appStoreMgr, networkMgr, flowEngine, feStore)
//	  CasaOSHandler(appStoreMgr, orchestrator, gatewayIP, domain)
//	  NPMHandler(npmMgr)
//	  HardwareHandler(halClient, setupMgr)
//	  StorageHandler(halClient)
//	  CommunicationHandler(halClient)
//	  MediaHandler(halClient, domain)
//	  LogsHandler(halClient)
//	  WSManager(systemMgr, networkMgr, monitoringMgr, docker)
//	  WSHandlers(wsManager)
//	  SMBHandler(storageMgr)
//	  BackupsHandler(backupMgr, halClient, destRegistry)
//	  UpdatesHandler(updateMgr, flowEngine, db.DB)
//	  MetricsHandler(metricsCollector, circuitBreakers, feStore, swarmMgr)
//
//	Phase 7 — HTTP Server & Router
//	  chi.NewRouter() with middleware stack:
//	    Logger → Recoverer → Metrics → RealIP → RequestID → CORS → Timeout → MaxBodySize → SetupRequired → JWTAuth
//	  Routes mounted under /api/v1/
//	  ListenAndServe with graceful shutdown (SIGINT/SIGTERM)
//
// ## Manager Dependency DAG
//
// Arrows show "depends on" relationships. No circular dependencies exist.
//
//	config ──────────────────┬──────────────────────────────────────────┐
//	                         │                                          │
//	database ────────────────┤                                          │
//	                         │                                          │
//	circuitbreaker ──────────┤                                          │
//	                         │                                          │
//	halClient ───────────────┼──→ SystemManager                        │
//	  │                      │      │                                   │
//	  │                      │      └──→ MonitoringManager ←── NetworkManager
//	  │                      │                                   │
//	  ├──→ FirewallManager ←─┘                                   │
//	  ├──→ VPNManager ←── cfg                                    │
//	  ├──→ MountsManager ←── cfg                                 │
//	  │                                                          │
//	  ├──→ SwarmManager ←── dockerCB                             │
//	  │      │                                                   │
//	  │      ├──→ PortManager ←── db                             │
//	  │      │      │                                            │
//	  │      └──→ Orchestrator ←── db, cfg, npmMgr, piholeMgr   │
//	  │              │                                           │
//	  │              └──→ AppStoreManager ←── dbMgr, piholeMgr, npmMgr, portMgr
//	  │                                                          │
//	  ├──→ SetupManager ←── cfg, db, fbClient, piholePwClient, npmMgr
//	  │                                                          │
//	  └──→ BackupManager ←── db                                  │
//	                                                             │
//	FlowEngine ←── WorkflowStore(db), ActivityRegistry           │
//	  │  (wired into: orchestrator, appStoreMgr, networkMgr,     │
//	  │   setupMgr, backupMgr)                                   │
//	  │                                                          │
//	  └──→ All handlers receive their dependencies from above    │
//	                                                             │
//	DockerManager ←── cfg, dockerCB                              │
//	WizardManager ←── cfg, docker                                │
//	UpdateManager ←── db ───────────────────────────────────────┘
//
// ## Verified Invariants
//
//   - No circular dependencies: the DAG is strictly layered (config → infra → managers → engine → handlers).
//   - Every manager that accesses the database receives db or db.DB.
//   - Every handler that accesses hardware receives halClient.
//   - FlowEngine is wired into managers via SetFlowEngine() after engine.Start().
//   - SwarmManager shares the same circuit breaker as DockerManager (same Docker daemon).
//   - Orchestrator is required for FlowEngine app activities (log.Fatal if nil).
//   - Graceful shutdown order: backup scheduler → FlowEngine → HTTP server.
package docs

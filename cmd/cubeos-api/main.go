// Package main CubeOS API
//
// CubeOS API provides REST endpoints for managing the CubeOS system,
// including hardware control, Docker services, network configuration,
// storage management, and communication devices.
//
//	@title						CubeOS API
//	@version					1.0
//	@description				REST API for CubeOS - Raspberry Pi server operating system
//	@termsOfService				https://cubeos.io/terms/
//
//	@contact.name				CubeOS Support
//	@contact.url				https://cubeos.io/support
//	@contact.email				support@cubeos.io
//
//	@license.name				Apache 2.0
//	@license.url				http://www.apache.org/licenses/LICENSE-2.0.html
//
//	@host						cubeos.cube:6010
//	@BasePath					/api/v1
//
//	@securityDefinitions.apikey	BearerAuth
//	@in							header
//	@name						Authorization
//	@description				JWT token for authentication. Format: "Bearer {token}"
//
//	@tag.name					Health
//	@tag.description			Health check and system status endpoints
//
//	@tag.name					Auth
//	@tag.description			Authentication endpoints (login, logout, token refresh)
//
//	@tag.name					System
//	@tag.description			System information and control
//
//	@tag.name					Network
//	@tag.description			Network interfaces, WiFi, AP management, network modes
//
//	@tag.name					Clients
//	@tag.description			Connected client management (DHCP leases)
//
//	@tag.name					Storage
//	@tag.description			Block devices, USB storage, network mounts
//
//	@tag.name					Docker
//	@tag.description			Docker container and service management
//
//	@tag.name					Categories
//	@tag.description			Application categories
//
//	@tag.name					Apps
//	@tag.description			Unified application management (Swarm-based)
//
//	@tag.name					AppStore
//	@tag.description			Application store and marketplace
//
//	@tag.name					VPN
//	@tag.description			VPN configuration (WireGuard, OpenVPN, Tor)
//
//	@tag.name					Mounts
//	@tag.description			Remote mount management (SMB, NFS)
//
//	@tag.name					Firewall
//	@tag.description			Firewall rules and port management
//
//	@tag.name					CasaOS
//	@tag.description			CasaOS app import and compatibility
//
//	@tag.name					Chat
//	@tag.description			AI assistant chat interface
//
//	@tag.name					Docs
//	@tag.description			Documentation viewer
//
//	@tag.name					FQDNs
//	@tag.description			FQDN and DNS record management
//
//	@tag.name					NPM
//	@tag.description			Nginx Proxy Manager integration
//
//	@tag.name					Ports
//	@tag.description			Port allocation and management
//
//	@tag.name					Profiles
//	@tag.description			System profiles (minimal, standard, full)
//
//	@tag.name					Registry
//	@tag.description			Local Docker registry management
//
//	@tag.name					Setup
//	@tag.description			First boot setup wizard
//
//	@tag.name					WebSocket
//	@tag.description			Real-time WebSocket connections
//
//	@tag.name					Hardware
//	@tag.description			Raspberry Pi hardware control (GPIO, I2C, sensors, power)
//
//	@tag.name					Communication
//	@tag.description			GPS, Cellular, Meshtastic, Iridium, Bluetooth
//
//	@tag.name					Media
//	@tag.description			Camera capture/streaming, audio devices
//
//	@tag.name					Logs
//	@tag.description			System logs (kernel, journal, hardware)
//
//	@tag.name					Backup
//	@tag.description			Backup and restore operations
//
//	@tag.name					Processes
//	@tag.description			System process management
//
//	@tag.name					Wizard
//	@tag.description			Setup wizard and recommendations
//
//	@tag.name					Monitoring
//	@tag.description			System monitoring and alerts
//
//	@tag.name					Preferences
//	@tag.description			User preferences management
//
//	@tag.name					Favorites
//	@tag.description			User favorites management
//
//	@tag.name					Power
//	@tag.description			Power management and UPS status
//
//	@tag.name					SMB
//	@tag.description			SMB share management
//
//	@tag.name					DiskHealth
//	@tag.description			Disk health monitoring (SMART)
//
//	@tag.name					Support
//	@tag.description			Support and diagnostic tools
package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog/log"
	httpSwagger "github.com/swaggo/http-swagger"
	"golang.org/x/crypto/bcrypt"

	"cubeos-api/internal/config"
	"cubeos-api/internal/database"
	"cubeos-api/internal/hal"
	"cubeos-api/internal/handlers"
	"cubeos-api/internal/managers"
	"cubeos-api/internal/middleware"
	"cubeos-api/internal/models"

	"cubeos-api/docs" // Import generated swagger docs (named for Host override)
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Override swagger host to empty string so it uses the browser's
	// current host (works correctly through NPM reverse proxy at port 80)
	docs.SwaggerInfo.Host = ""

	// Setup logging (zerolog)
	log.Info().Str("version", cfg.Version).Msg("starting CubeOS API")

	// Warn if using default JWT secret
	if cfg.JWTSecret == "cubeos-dev-secret-change-in-production" {
		log.Warn().Msg("using default JWT secret — set JWT_SECRET in secrets.env for production")
	}

	// Connect to database
	// Open database using pure-Go driver
	rawDB, err := database.Open(cfg.DatabasePath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to open database")
	}
	db := sqlx.NewDb(rawDB, "sqlite")
	defer db.Close()

	// Initialize database schema + run migrations (single source of truth: database/schema.go)
	// Schema init is critical — without tables, the API cannot function.
	// Migration failures are non-critical — existing schema can still serve traffic.
	log.Info().Msg("initializing database schema and running migrations")
	if err := database.InitSchema(db.DB); err != nil {
		log.Fatal().Err(err).Msg("failed to initialize database schema")
	}
	if err := database.Migrate(db.DB); err != nil {
		log.Warn().Err(err).Msg("database migration failed (existing schema still usable)")
	} else {
		log.Info().Msg("database schema and migrations completed successfully")
	}

	// Seed default admin user (after schema is created)
	if err := seedDefaultAdmin(db); err != nil {
		log.Warn().Err(err).Msg("failed to seed admin user")
	}

	// Create Docker manager
	docker, err := managers.NewDockerManager(cfg)
	if err != nil {
		log.Warn().Err(err).Msg("failed to connect to Docker")
		docker = nil
	}
	if docker != nil {
		defer docker.Close()
	}

	// Create HAL client for hardware access (Sprint 3)
	// HAL runs on host network at port 6005, accessible from container via host IP
	halURL := os.Getenv("HAL_URL")
	if halURL == "" {
		halURL = hal.DefaultHALURL
	}
	halClient := hal.NewClient(halURL)
	log.Info().Str("endpoint", halURL).Msg("HAL client initialized")

	// Create core managers (with HAL client for hardware access)
	systemMgr := managers.NewSystemManager(halClient)
	networkMgr := managers.NewNetworkManager(cfg, halClient, db)

	// Create extended managers
	logMgr := managers.NewLogManager()
	firewallMgr := managers.NewFirewallManager(cfg, halClient)
	backupMgr := managers.NewBackupManager()
	processMgr := managers.NewProcessManager()
	monitoringMgr := managers.NewMonitoringManager(systemMgr, networkMgr)
	prefMgr := managers.NewPreferencesManager()
	wizardMgr := managers.NewWizardManager(cfg, docker)
	powerMgr := managers.NewPowerManager()
	storageMgr := managers.NewStorageManager()

	// Create App Store manager
	dbMgr := managers.NewDatabaseManager(db.DB)

	// Create PiholeManager early so it can be used by AppStoreManager
	piholeMgr := managers.NewPiholeManager(cfg, "/cubeos")
	log.Info().Msg("PiholeManager initialized")

	// Create NPM manager for proxy host management (Sprint 4)
	// Must be initialized before AppStoreManager which depends on it
	npmMgr := managers.NewNPMManager(cfg, "/cubeos/config")
	if err := npmMgr.Init(); err != nil {
		log.Warn().Err(err).Msg("NPM authentication failed")
	} else {
		log.Info().Msg("NPMManager initialized successfully")
		// Seed core proxy rules on first boot (idempotent — skips existing rules)
		if created, err := npmMgr.EnsureCoreProxyHosts(); err != nil {
			log.Warn().Err(err).Msg("NPM: failed to seed core proxy rules")
		} else if created > 0 {
			log.Info().Int("count", created).Msg("NPM: seeded core proxy rules for out-of-box experience")
		}
	}

	// Create shared SwarmManager (used by Orchestrator and PortManager)
	// Single Docker client instance shared across components.
	swarmMgr, err := managers.NewSwarmManager()
	if err != nil {
		log.Warn().Err(err).Msg("failed to create SwarmManager (port validation will use DB-only mode)")
		// swarmMgr is nil — PortManager and Orchestrator degrade gracefully
	} else {
		log.Info().Msg("SwarmManager initialized (shared instance)")
	}

	// Create PortManager for port allocation with triple-source validation (DB + Swarm + HAL)
	portMgr := managers.NewPortManager(db.DB, swarmMgr, halClient)
	log.Info().Msg("PortManager initialized with triple-source validation")

	appStoreMgr := managers.NewAppStoreManager(cfg, dbMgr, cfg.DataDir, piholeMgr, npmMgr, portMgr)

	// B3: Auto-sync app store catalog when switching to an online network mode.
	// Runs in background goroutine so it doesn't block the mode switch response.
	networkMgr.SetOnModeChange(func(mode models.NetworkMode) {
		if mode != models.NetworkModeOffline {
			go func() {
				log.Info().Str("mode", string(mode)).Msg("Network mode changed to online — syncing app store catalog")
				if err := appStoreMgr.SyncAllStores(); err != nil {
					log.Warn().Err(err).Msg("Auto-sync app store catalog failed (may not have internet yet)")
				} else {
					log.Info().Msg("App store catalog auto-synced successfully")
				}
			}()
		}
	})

	// Resolve registry URL early (used by both Orchestrator and RegistryHandler)
	registryURL := os.Getenv("REGISTRY_URL")
	if registryURL == "" {
		registryURL = "http://" + cfg.GatewayIP + ":5000"
	}

	// Create Orchestrator for unified app management (Sprint 3)
	orchestrator, err := managers.NewOrchestrator(managers.OrchestratorConfig{
		DB:            db.DB,
		Config:        cfg,
		CoreappsPath:  "/cubeos/coreapps",
		AppsPath:      "/cubeos/apps",
		HALClient:     halClient,
		SwarmManager:  swarmMgr,
		NPMManager:    npmMgr,
		PiholeManager: piholeMgr,
		RegistryURL:   registryURL,
	})
	if err != nil {
		log.Warn().Err(err).Msg("failed to create Orchestrator")
		// Continue without orchestrator for backward compatibility
	} else {
		defer orchestrator.Close()
		log.Info().Msg("Orchestrator initialized successfully")

		// Sync Swarm stacks into apps table (B22: ensures dashboard shows all services)
		syncCtx, syncCancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := orchestrator.SyncAppsFromSwarm(syncCtx); err != nil {
			log.Warn().Err(err).Msg("SyncAppsFromSwarm failed (non-fatal)")
		}
		syncCancel()

		// Seed system apps that aren't Swarm stacks (compose services: pihole, npm, hal)
		// Also updates display names for apps already registered with raw names.
		seedAppsCtx, seedAppsCancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := orchestrator.SeedSystemApps(seedAppsCtx); err != nil {
			log.Warn().Err(err).Msg("SeedSystemApps failed (non-fatal)")
		}
		seedAppsCancel()

		// Seed port allocations and FQDNs for system services (B26, B28)
		// Must run after SyncAppsFromSwarm so app records exist for foreign keys
		seedCtx, seedCancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := orchestrator.SeedSystemPortsAndFQDNs(seedCtx); err != nil {
			log.Warn().Err(err).Msg("SeedSystemPortsAndFQDNs failed (non-fatal)")
		}
		seedCancel()

		// Prune orphan app records (ghost entries with no matching Docker service)
		pruneCtx, pruneCancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := orchestrator.PruneOrphanApps(pruneCtx); err != nil {
			log.Warn().Err(err).Msg("PruneOrphanApps failed (non-fatal)")
		}
		pruneCancel()
	}

	// Create VPN manager (Sprint 3 - with HAL client)
	vpnMgr := managers.NewVPNManager(cfg, halClient)
	log.Info().Msg("VPNManager initialized (HAL-enabled)")

	// Create Mounts manager (Sprint 3 - with HAL client)
	mountsMgr := managers.NewMountsManager(cfg, halClient)
	log.Info().Msg("MountsManager initialized (HAL-enabled)")
	mountsMgr.SetDB(db.DB) // FIX: Wire database connection

	// Create Setup manager (first boot wizard)
	setupMgr := managers.NewSetupManager(cfg, db.DB, halClient)

	// Create handlers
	h := handlers.NewHandlers(cfg, db, docker, halClient, systemMgr, networkMgr)
	ext := handlers.NewExtendedHandlers(logMgr, firewallMgr, backupMgr, processMgr, wizardMgr, monitoringMgr, prefMgr, powerMgr, storageMgr, halClient)
	appStoreHandler := handlers.NewAppStoreHandler(appStoreMgr, npmMgr)
	setupHandler := handlers.NewSetupHandler(setupMgr)

	// Create Chat handler (AI Assistant)
	chatHandler := handlers.NewChatHandler(cfg)

	// Create Docs handler (Documentation viewer)
	docsHandler := handlers.NewDocsHandler()

	// Create unified API handlers (Sprint 3)
	var appsHandler *handlers.AppsHandler
	var profilesHandler *handlers.ProfilesHandler
	if orchestrator != nil {
		appsHandler = handlers.NewAppsHandler(orchestrator)
		profilesHandler = handlers.NewProfilesHandler(orchestrator)
		log.Info().Msg("AppsHandler and ProfilesHandler initialized")
	}

	// Create NetworkHandler for network mode management (Sprint 3)
	networkHandler := handlers.NewNetworkHandler(networkMgr, halClient)

	// Create FirewallHandler for firewall management (Sprint 5C)
	firewallHandler := handlers.NewFirewallHandler(firewallMgr, halClient)
	log.Info().Msg("FirewallHandler initialized")

	// Create VPN and Mounts handlers (Sprint 3)
	vpnHandler := handlers.NewVPNHandler(vpnMgr)
	mountsHandler := handlers.NewMountsHandler(mountsMgr)
	log.Info().Msg("VPNHandler and MountsHandler initialized")

	// Create Ports, FQDNs, and Registry handlers (Sprint 4)
	portsHandler := handlers.NewPortsHandler(portMgr)

	// PiholeManager already created earlier (used by AppStoreManager)

	fqdnsHandler := handlers.NewFQDNsHandler(db.DB, npmMgr, piholeMgr)
	registryPath := os.Getenv("REGISTRY_PATH")
	if registryPath == "" {
		registryPath = "/cubeos/data/registry"
	}
	registryHandler := handlers.NewRegistryHandler(registryURL, registryPath, portMgr, orchestrator)
	log.Info().Msg("PortsHandler, FQDNsHandler, and RegistryHandler initialized")

	// Create CasaOS Import handler (Sprint 4D)
	casaosHandler := handlers.NewCasaOSHandler(appStoreMgr, orchestrator, cfg.GatewayIP, cfg.Domain)
	log.Info().Msg("CasaOSHandler initialized")

	// Create NPM handler (Sprint 4E)
	npmHandler := handlers.NewNPMHandler(npmMgr)
	log.Info().Msg("NPMHandler initialized")

	// Create HAL-based handlers (Sprint 6)
	hardwareHandler := handlers.NewHardwareHandler(halClient, setupMgr)
	halStorageHandler := handlers.NewStorageHandler(halClient)
	communicationHandler := handlers.NewCommunicationHandler(halClient)
	mediaHandler := handlers.NewMediaHandler(halClient, cfg.Domain)
	halLogsHandler := handlers.NewLogsHandler(halClient)
	log.Info().Msg("HAL handlers initialized (Hardware, Storage, Communication, Media, Logs)")

	// Create WebSocket manager and handlers
	wsManager := handlers.NewWSManager(systemMgr, networkMgr, monitoringMgr, docker)
	wsHandlers := handlers.NewWSHandlers(wsManager)

	// Create SMB handler
	smbHandler := handlers.NewSMBHandler(storageMgr)
	log.Info().Msg("SMBHandler initialized")

	// Create Backups handler (wired to BackupManager)
	backupsHandler := handlers.NewBackupsHandler(backupMgr)
	log.Info().Msg("BackupsHandler initialized (wired to BackupManager)")

	// Apply saved UPS configuration to HAL on startup (non-blocking)
	go func() {
		// Wait for HAL to be ready
		time.Sleep(5 * time.Second)

		model := setupMgr.GetConfig("ups_model")
		if model == "" || model == "none" {
			log.Info().Msg("UPS: no saved configuration — power monitor idle")
			return
		}

		log.Info().Str("model", model).Msg("UPS: applying saved configuration to HAL")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if _, err := halClient.ConfigureUPS(ctx, model); err != nil {
			log.Warn().Err(err).Str("model", model).Msg("UPS: failed to apply saved config to HAL (user can re-apply from dashboard)")
		} else {
			log.Info().Str("model", model).Msg("UPS: saved configuration applied successfully")
		}
	}()

	// Create router
	r := chi.NewRouter()

	// Middleware
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)
	r.Use(chimw.RealIP)
	r.Use(chimw.RequestID)

	// CORS must come before Timeout so OPTIONS preflight responses aren't delayed
	// Build allowed origins from config — restrict to known dashboard locations
	allowedOrigins := []string{
		fmt.Sprintf("http://%s:%d", cfg.GatewayIP, cfg.DashboardPort),
		fmt.Sprintf("https://%s:%d", cfg.GatewayIP, cfg.DashboardPort),
		fmt.Sprintf("http://%s:%d", cfg.Domain, cfg.DashboardPort),
		fmt.Sprintf("https://%s:%d", cfg.Domain, cfg.DashboardPort),
		fmt.Sprintf("http://%s", cfg.Domain),
		fmt.Sprintf("https://%s", cfg.Domain),
	}
	// Allow additional origins from env (comma-separated)
	if extra := os.Getenv("CORS_ALLOWED_ORIGINS"); extra != "" {
		for _, origin := range strings.Split(extra, ",") {
			if o := strings.TrimSpace(origin); o != "" {
				allowedOrigins = append(allowedOrigins, o)
			}
		}
	}

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Use(chimw.Timeout(60 * time.Second))

	// Global body size limit: 10MB (prevents OOM from oversized requests)
	r.Use(middleware.MaxBodySize(10 * 1024 * 1024))

	// Setup-required guard: blocks API requests until first boot setup is complete.
	// Allows: /health, /api/v1/setup/*, /api/v1/auth/login
	r.Use(handlers.SetupRequiredMiddleware(setupMgr))

	// Public routes
	r.Get("/health", h.Health)

	// Debug profiling (gated by env var for safety)
	if os.Getenv("CUBEOS_ENABLE_PPROF") == "1" {
		r.HandleFunc("/debug/pprof/", pprof.Index)
		r.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		r.HandleFunc("/debug/pprof/profile", pprof.Profile)
		r.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		r.HandleFunc("/debug/pprof/trace", pprof.Trace)
		r.Handle("/debug/pprof/heap", pprof.Handler("heap"))
		r.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
		r.Handle("/debug/pprof/allocs", pprof.Handler("allocs"))
		r.Handle("/debug/pprof/block", pprof.Handler("block"))
		r.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
		log.Warn().Msg("pprof debug endpoints enabled at /debug/pprof/ (CUBEOS_ENABLE_PPROF=1)")
	}

	// NOTE: WebSocket endpoints moved inside /api/v1/ws (auth-protected).
	// The /monitoring/websocket endpoint also provides authenticated WS access.

	// API v1 routes
	r.Route("/api/v1", func(r chi.Router) {
		// Swagger documentation (public, no auth required)
		// B06: Use absolute path for doc.json so it resolves correctly through NPM proxy.
		// Relative "doc.json" can fail when the browser base URL differs from the
		// API's actual path (e.g., api.cubeos.cube vs 10.42.24.1:6010).
		r.Get("/swagger/*", httpSwagger.Handler(
			httpSwagger.URL("/api/v1/swagger/doc.json"),
			httpSwagger.DeepLinking(true),
			httpSwagger.DocExpansion("none"),
			httpSwagger.DomID("swagger-ui"),
		))

		// Public auth routes
		r.Post("/auth/login", h.Login)

		// Token refresh — uses lenient JWT middleware (accepts recently-expired tokens)
		r.Group(func(r chi.Router) {
			r.Use(middleware.JWTAuthAllowExpired(cfg))
			r.Post("/auth/refresh", h.RefreshToken)
		})

		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(middleware.JWTAuth(cfg))

			// Auth routes
			r.Route("/auth", func(r chi.Router) {
				r.Post("/logout", h.Logout)
				r.Get("/me", h.GetMe)
				r.Post("/password", h.ChangePassword)
			})

			// System Info
			r.Route("/system", func(r chi.Router) {
				r.Get("/info", h.GetSystemInfo)
				r.Get("/stats", h.GetSystemStats)
				r.Get("/temperature", h.GetTemperature)
				r.Get("/hostname", h.GetHostname)
				r.Post("/hostname", h.SetHostname)
				r.Get("/timezone", h.GetTimezone)
				r.Post("/timezone", h.SetTimezone)
				r.Get("/timezones", h.GetTimezones)
				r.Post("/reboot", h.Reboot)
				r.Post("/shutdown", h.Shutdown)
				r.Get("/browse", appStoreHandler.BrowseDirectories)
			})

			// Network Management (all routes via NetworkHandler)
			r.Mount("/network", networkHandler.Routes())

			// Connected Clients (DHCP)
			r.Route("/clients", func(r chi.Router) {
				r.Get("/", h.GetConnectedClients)
				r.Get("/count", h.GetClientCount)
				r.Post("/{mac}/block", h.BlockClient)
				r.Post("/{mac}/unblock", h.UnblockClient)
			})

			// Storage (disk health and overview — mounts via /mounts API)
			r.Route("/storage", func(r chi.Router) {
				r.Get("/", h.GetStorage)
				r.Get("/health", ext.GetDiskHealth)
				r.Get("/health/{device}", ext.GetDiskHealthByDevice)
			})

			// Services
			r.Route("/services", func(r chi.Router) {
				r.Get("/", h.ListServices)
				r.Get("/{name}", h.GetService)
				r.Post("/{name}/start", h.StartService)
				r.Post("/{name}/stop", h.StopService)
				r.Post("/{name}/restart", h.RestartService)
				r.Post("/{name}/enable", h.EnableService)
				r.Post("/{name}/disable", h.DisableService)
			})

			// Docker Management
			r.Route("/docker", func(r chi.Router) {
				r.Post("/prune", h.DockerPrune)
				r.Get("/disk-usage", h.DockerDiskUsage)
				r.Get("/disk", h.DockerDiskUsage) // Alias for backward compat
			})

			// ===========================================================
			// Extended APIs
			// ===========================================================

			// Logs (legacy - system logs)
			r.Route("/logs", func(r chi.Router) {
				r.Get("/journal", ext.GetJournalLogs)
				r.Get("/units", ext.GetLogUnits)
				r.Get("/service/{service}", ext.GetServiceLogs)
				r.Get("/container/{container}", ext.GetContainerLogs)
				r.Get("/kernel", ext.GetKernelLogs)
				r.Get("/boot", ext.GetBootLogs)
				r.Get("/file", ext.ReadLogFile)
				r.Get("/errors", ext.GetRecentErrors)
			})

			// Firewall (Sprint 5C - using dedicated FirewallHandler)
			r.Mount("/firewall", firewallHandler.Routes())

			// Backups - use handler instead of inline routes
			r.Mount("/backups", backupsHandler.Routes())

			// Processes
			r.Route("/processes", func(r chi.Router) {
				r.Get("/", ext.ListProcesses)
				r.Get("/stats/summary", ext.GetProcessStats)
				r.Get("/top/cpu", ext.TopCPUProcesses)
				r.Get("/top/memory", ext.TopMemoryProcesses)
				r.Get("/search/{name}", ext.SearchProcesses)
				r.Get("/{pid}", ext.GetProcess)
				r.Post("/{pid}/kill", ext.KillProcess)
				r.Post("/{pid}/terminate", ext.TerminateProcess)
			})

			// Wizard
			r.Route("/wizard", func(r chi.Router) {
				r.Get("/profiles", ext.GetProfiles)
				r.Get("/services", ext.GetWizardServices)
				r.Get("/recommendations", ext.GetRecommendations)
				r.Post("/apply", ext.ApplyProfile) // Fixed: was /apply-profile
				r.Post("/estimate", ext.EstimateResources)
			})

			// Monitoring
			r.Route("/monitoring", func(r chi.Router) {
				r.Get("/stats", ext.GetMonitoringStats)
				r.Get("/history", ext.GetStatsHistory)
				r.Get("/thresholds", ext.GetAlertThresholds)   // Fixed: was /alerts/thresholds
				r.Put("/thresholds", ext.SetAlertThresholds)   // Fixed: was /alerts/thresholds
				r.Get("/alerts", ext.GetCurrentAlerts)         // Fixed: was /alerts/current
				r.Get("/websocket", wsHandlers.StatsWebSocket) // Add WebSocket endpoint
			})

			// Power/UPS (legacy)
			r.Route("/power", func(r chi.Router) {
				r.Get("/status", ext.GetPowerStatus)
				r.Post("/charging", ext.SetCharging)
				r.Put("/charging", ext.SetCharging)
			})

			// Preferences
			r.Get("/preferences", ext.GetPreferences)
			r.Post("/preferences", ext.SetPreferences)
			r.Put("/preferences", ext.SetPreferences)
			r.Post("/preferences/reset", ext.ResetPreferences) // Added
			r.Post("/preferences/wallpaper", ext.UploadWallpaper)
			r.Get("/preferences/wallpaper", ext.GetWallpaper)
			r.Delete("/preferences/wallpaper", ext.DeleteWallpaper)

			// Favorites
			r.Get("/favorites", ext.GetFavorites)
			r.Post("/favorites/{name}", ext.AddFavorite)
			r.Delete("/favorites/{name}", ext.RemoveFavorite)
			r.Post("/favorites/{name}/toggle", ext.ToggleFavorite) // Fixed: was PUT

			// App Store
			r.Mount("/appstore", appStoreHandler.Routes())

			// Chat (AI Assistant)
			r.Mount("/chat", chatHandler.Routes())

			// Documentation (offline docs viewer)
			r.Mount("/documentation", docsHandler.Routes())

			// Unified Apps API (Sprint 3)
			if appsHandler != nil {
				r.Mount("/apps", appsHandler.Routes())
			} else {
				r.Mount("/apps", unavailableHandler("Orchestrator unavailable — apps API requires a working Orchestrator"))
			}

			// Profiles API (Sprint 3)
			if profilesHandler != nil {
				r.Mount("/profiles", profilesHandler.Routes())
			} else {
				r.Mount("/profiles", unavailableHandler("Orchestrator unavailable — profiles API requires a working Orchestrator"))
			}

			// VPN API (Sprint 3)
			r.Mount("/vpn", vpnHandler.Routes())

			// Mounts API (Sprint 3)
			r.Mount("/mounts", mountsHandler.Routes())

			// Ports API (Sprint 4)
			r.Mount("/ports", portsHandler.Routes())

			// FQDNs API (Sprint 4)
			r.Mount("/fqdns", fqdnsHandler.Routes())

			// Registry API (Sprint 4)
			r.Mount("/registry", registryHandler.Routes())

			// CasaOS Import API (Sprint 4D)
			r.Mount("/casaos", casaosHandler.Routes())

			// NPM API (Sprint 4E)
			r.Mount("/npm", npmHandler.Routes())

			// ===========================================================
			// HAL-based Hardware APIs (Sprint 6)
			// ===========================================================

			// Support Bundle (diagnostic download via HAL)
			r.Get("/support/bundle.zip", hardwareHandler.GetSupportBundle)

			// Hardware API - System info, power, RTC, watchdog, GPIO, I2C, sensors
			// 35 endpoints for Pi-specific hardware access
			r.Mount("/hardware", hardwareHandler.Routes())

			// HAL Storage API - Block devices, USB storage, network mounts via HAL
			// 19 endpoints (separate from legacy /storage which handles SMB shares)
			r.Mount("/hal/storage", halStorageHandler.Routes())

			// Communication API - GPS, Cellular, Meshtastic, Iridium, Bluetooth
			// 29 endpoints for communication devices
			r.Mount("/communication", communicationHandler.Routes())

			// Media API - Camera capture/streaming, audio devices/volume
			// 13 endpoints for media hardware
			r.Mount("/media", mediaHandler.Routes())

			// HAL Logs API - Kernel, journal, hardware logs via HAL
			// 4 endpoints (separate from legacy /logs which has more options)
			r.Mount("/hal/logs", halLogsHandler.Routes())

			// SMB/Samba shares management
			r.Mount("/smb", smbHandler.Routes())

			// WebSocket endpoints
			r.Mount("/ws", wsHandlers.Routes())

		})

		// Setup wizard routes (semi-public - accessible before full setup)
		r.Mount("/setup", setupHandler.Routes())
	})

	// Legacy /api routes removed — all endpoints are under /api/v1.
	// Dashboard and clients should use /api/v1/{resource} exclusively.

	// Start server with graceful shutdown
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Channel to listen for shutdown signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Info().Str("addr", addr).Msg("API listening")
		log.Info().Str("url", "http://"+addr+"/api/v1/swagger/index.html").Msg("Swagger UI available")
		log.Info().Msg("HAL endpoints: /hardware, /hal/storage, /communication, /media, /hal/logs, /support/bundle.zip")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("server failed")
		}
	}()

	// Block until signal received
	sig := <-quit
	log.Info().Str("signal", sig.String()).Msg("received signal, shutting down gracefully")

	// Give active connections 15 seconds to finish
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal().Err(err).Msg("server forced to shutdown")
	}
	log.Info().Msg("server stopped")
}

// unavailableHandler returns a chi router that responds with 503 for all routes.
// Used when a subsystem (e.g. Orchestrator) fails to initialize but the API
// should still advertise the endpoint with a helpful error instead of hiding it.
func unavailableHandler(message string) chi.Router {
	r := chi.NewRouter()
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, `{"error":%q,"code":503}`, message)
	}
	r.HandleFunc("/*", handler)
	r.HandleFunc("/", handler)
	return r
}

// seedDefaultAdmin creates a default admin user if none exists.
// Table creation is handled by database.InitSchema() — do NOT create tables here.
func seedDefaultAdmin(db *sqlx.DB) error {
	var count int
	if err := db.Get(&count, "SELECT COUNT(*) FROM users WHERE username = 'admin'"); err != nil {
		return fmt.Errorf("failed to check admin user: %w", err)
	}
	if count == 0 {
		hash, err := bcrypt.GenerateFromPassword([]byte("cubeos"), config.BcryptCost)
		if err != nil {
			return fmt.Errorf("failed to hash default password: %w", err)
		}

		_, err = db.Exec(
			"INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
			"admin", string(hash), "admin",
		)
		if err != nil {
			return err
		}
		log.Info().Msg("created default admin user (change password on first login)")
	}

	return nil
}

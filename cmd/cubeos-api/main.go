package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"

	"cubeos-api/internal/config"
	"cubeos-api/internal/database"
	"cubeos-api/internal/hal"
	"cubeos-api/internal/handlers"
	"cubeos-api/internal/managers"
	"cubeos-api/internal/middleware"
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Setup logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("Starting CubeOS API v%s", cfg.Version)

	// Connect to database
	// Open database using pure-Go driver
	rawDB, err := database.Open(cfg.DatabasePath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	db := sqlx.NewDb(rawDB, "sqlite")
	defer db.Close()

	// Initialize database schema
	if err := initDB(db); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Run database migrations (Sprint 2+)
	log.Printf("Running database migrations...")
	if err := database.MigrateAndSeed(db.DB); err != nil {
		log.Printf("Warning: Migration failed: %v", err)
		// Continue - migrations are not critical for basic operation
	} else {
		log.Printf("Database migrations completed successfully")
	}

	// Create Docker manager
	docker, err := managers.NewDockerManager(cfg)
	if err != nil {
		log.Printf("Warning: Failed to connect to Docker: %v", err)
		docker = nil
	}
	if docker != nil {
		defer docker.Close()
	}

	// Create HAL client for hardware access (Sprint 3)
	// HAL runs on host network at port 6005, accessible from container via host IP
	halClient := hal.NewClient("http://10.42.24.1:6005")
	log.Printf("HAL client initialized (endpoint: http://10.42.24.1:6005)")

	// Create core managers (with HAL client for hardware access)
	systemMgr := managers.NewSystemManager()
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
	appStoreMgr := managers.NewAppStoreManager(cfg, dbMgr, cfg.DataDir)

	// Create Orchestrator for unified app management (Sprint 3)
	orchestrator, err := managers.NewOrchestrator(managers.OrchestratorConfig{
		DB:           db.DB,
		Config:       cfg,
		CoreappsPath: "/cubeos/coreapps",
		AppsPath:     "/cubeos/apps",
		PiholePath:   "/cubeos/coreapps/pihole/appdata",
		NPMConfigDir: "/cubeos/coreapps/npm/appdata",
	})
	if err != nil {
		log.Printf("Warning: Failed to create Orchestrator: %v", err)
		// Continue without orchestrator for backward compatibility
	} else {
		defer orchestrator.Close()
		log.Printf("Orchestrator initialized successfully")
	}

	// Create VPN manager (Sprint 3 - with HAL client)
	vpnMgr := managers.NewVPNManager(cfg, halClient)
	log.Printf("VPNManager initialized (HAL-enabled)")

	// Create Mounts manager (Sprint 3 - with HAL client)
	mountsMgr := managers.NewMountsManager(cfg, halClient)
	log.Printf("MountsManager initialized (HAL-enabled)")
	mountsMgr.SetDB(db.DB) // FIX: Wire database connection

	// Create NPM manager for proxy host management (Sprint 4)
	npmMgr := managers.NewNPMManager(cfg, "/cubeos/config")
	// Initialize NPM authentication (creates service account if needed)
	if err := npmMgr.Init(); err != nil {
		log.Printf("Warning: NPM authentication failed: %v", err)
	} else {
		log.Printf("NPMManager initialized successfully")
	}

	// Create PortManager for port allocation (Sprint 4)
	portMgr := managers.NewPortManager(db.DB)
	log.Printf("PortManager initialized")

	// Create Setup manager (first boot wizard)
	setupMgr := managers.NewSetupManager(cfg, db.DB)

	// Create handlers
	h := handlers.NewHandlers(cfg, db, docker, halClient)
	ext := handlers.NewExtendedHandlers(logMgr, firewallMgr, backupMgr, processMgr, wizardMgr, monitoringMgr, prefMgr, powerMgr, storageMgr)
	appStoreHandler := handlers.NewAppStoreHandler(appStoreMgr)
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
		log.Printf("AppsHandler and ProfilesHandler initialized")
	}

	// Create NetworkHandler for network mode management (Sprint 3)
	networkHandler := handlers.NewNetworkHandler(networkMgr, halClient)

	// Create FirewallHandler for firewall management (Sprint 5C)
	firewallHandler := handlers.NewFirewallHandler(firewallMgr, halClient)
	log.Printf("FirewallHandler initialized")

	// Create VPN and Mounts handlers (Sprint 3)
	vpnHandler := handlers.NewVPNHandler(vpnMgr)
	mountsHandler := handlers.NewMountsHandler(mountsMgr)
	log.Printf("VPNHandler and MountsHandler initialized")

	// Create Ports, FQDNs, and Registry handlers (Sprint 4)
	portsHandler := handlers.NewPortsHandler(portMgr)
	fqdnsHandler := handlers.NewFQDNsHandler(db.DB, nil, nil) // NPM/Pihole managers optional
	registryHandler := handlers.NewRegistryHandler("http://10.42.24.1:5000", "/cubeos/data/registry")
	log.Printf("PortsHandler, FQDNsHandler, and RegistryHandler initialized")

	// Create CasaOS Import handler (Sprint 4D)
	casaosHandler := handlers.NewCasaOSHandler(appStoreMgr, cfg.GatewayIP, cfg.Domain)
	log.Printf("CasaOSHandler initialized")

	// Create NPM handler (Sprint 4E)
	npmHandler := handlers.NewNPMHandler(npmMgr)
	log.Printf("NPMHandler initialized")

	// Create WebSocket manager and handlers
	wsManager := handlers.NewWSManager(systemMgr, networkMgr, monitoringMgr, docker)
	wsHandlers := handlers.NewWSHandlers(wsManager)

	// Start background tasks
	stopCh := make(chan struct{})
	defer close(stopCh)

	// Start stats recording (every 2 seconds)
	go monitoringMgr.StartRecording(2*time.Second, stopCh)

	// Sync app stores in background
	go func() {
		time.Sleep(5 * time.Second) // Wait for startup
		log.Println("Syncing app stores...")
		if err := appStoreMgr.SyncAllStores(); err != nil {
			log.Printf("Warning: Failed to sync app stores: %v", err)
		} else {
			log.Println("App stores synced successfully")
		}
	}()

	// Create router
	r := chi.NewRouter()

	// Middleware
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)
	r.Use(chimw.RealIP)
	r.Use(chimw.Timeout(60 * time.Second))

	// CORS
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Requested-With"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Public routes
	r.Get("/health", h.Health)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/health", http.StatusTemporaryRedirect)
	})

	// OpenAPI spec endpoint
	r.Get("/api/v1/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-yaml")
		http.ServeFile(w, r, "openapi.yaml")
	})
	r.Get("/api/v1/docs", func(w http.ResponseWriter, r *http.Request) {
		// Serve Swagger UI HTML
		html := `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>CubeOS API Documentation</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui.css">
  <style>
    body { margin: 0; padding: 0; }
    .swagger-ui .topbar { display: none; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-bundle.js"></script>
  <script>
    SwaggerUIBundle({
      url: '/api/v1/openapi.yaml',
      dom_id: '#swagger-ui',
      presets: [SwaggerUIBundle.presets.apis],
      layout: "BaseLayout"
    });
  </script>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
	})

	// WebSocket routes (no JWT for initial connection, but needs token in query)
	r.Get("/ws/stats", wsHandlers.StatsWebSocket)
	r.Get("/api/monitoring/ws", wsHandlers.MonitoringWebSocket)

	// API v1 routes
	r.Route("/api/v1", func(r chi.Router) {
		// Authentication (public)
		r.Post("/auth/login", h.Login)

		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(middleware.JWTAuth(cfg))

			// Auth
			r.Post("/auth/refresh", h.RefreshToken)
			r.Get("/auth/me", h.GetMe)
			r.Post("/auth/password", h.ChangePassword)

			// System
			r.Route("/system", func(r chi.Router) {
				r.Get("/info", h.GetSystemInfo)
				r.Get("/stats", h.GetSystemStats)
				r.Get("/temperature", h.GetTemperature)
				r.Get("/uptime", h.GetUptime)
				r.Get("/hostname", h.GetHostname)
				r.Get("/datetime", h.GetDateTime)
				r.Get("/storage", h.GetStorageOverview) // Alias for frontend
				r.Post("/reboot", h.Reboot)
				r.Post("/shutdown", h.Shutdown)
				r.Post("/cancel-shutdown", h.CancelShutdown)

				// Systemd services
				r.Get("/services", h.GetSystemdServices)
				r.Get("/services/{service}", h.GetSystemdService)
				r.Post("/services/{service}/restart", h.RestartSystemdService)
			})

			// Network - all network routes consolidated here (including Sprint 3)
			r.Route("/network", func(r chi.Router) {
				r.Get("/interfaces", h.GetNetworkInterfaces)
				r.Get("/interfaces/detailed", h.GetNetworkInterfacesDetailed)
				r.Get("/interfaces/{name}", h.GetNetworkInterface)
				r.Get("/internet", h.CheckInternet)
				r.Get("/traffic", h.GetTrafficStats)
				r.Get("/traffic/{interface}/history", h.GetTrafficHistory)

				// WiFi AP
				r.Get("/wifi/ap/status", h.GetAPStatus)
				r.Get("/wifi/ap/config", h.GetAPConfig)
				r.Put("/wifi/ap/config", h.UpdateAPConfig)
				r.Post("/wifi/ap/restart", h.RestartAP)
				r.Get("/wifi/ap/clients", h.GetClients)
				r.Post("/wifi/ap/clients/{mac}/kick", h.KickClient)
				r.Post("/wifi/ap/clients/{mac}/block", h.BlockClient)

				// Legacy AP routes (for backward compatibility)
				r.Get("/ap/status", h.GetAPStatus)
				r.Get("/ap/config", h.GetAPConfig)
				r.Put("/ap/config", h.UpdateAPConfig)
				r.Post("/ap/restart", h.RestartAP)
				// FIX: Add /ap/clients route for Sprint 3 test compatibility
				r.Get("/ap/clients", networkHandler.GetAPClients)

				// DHCP
				r.Get("/dhcp/leases", h.GetDHCPLeases)

				// Sprint 3: Network mode switching (via HAL)
				r.Get("/status", networkHandler.GetNetworkStatus)
				r.Post("/mode", networkHandler.SetNetworkMode)
				r.Get("/wifi/scan", networkHandler.ScanWiFiNetworks)
				r.Post("/wifi/connect", networkHandler.ConnectToWiFi)
				// Network Modes V2 - Settings and VPN overlay
				r.Get("/settings", networkHandler.GetNetworkSettings)
				r.Put("/settings", networkHandler.UpdateNetworkSettings)
				r.Get("/vpn/mode", networkHandler.GetVPNMode)
				r.Post("/vpn/mode", networkHandler.SetVPNMode)
				r.Post("/warning/dismiss", networkHandler.DismissServerModeWarning)
			})

			// Clients (WiFi)
			r.Route("/clients", func(r chi.Router) {
				r.Get("/", h.GetClients)
				r.Get("/count", h.GetClientCount)
				r.Get("/stats", h.GetClientStats)
				r.Get("/blocked", h.GetBlockedClients)
				r.Post("/block/{mac}", h.BlockClient)
				r.Post("/unblock/{mac}", h.UnblockClient)
				r.Post("/kick/{mac}", h.KickClient)
			})

			// Storage
			r.Route("/storage", func(r chi.Router) {
				r.Get("/disks", h.GetDisks)
				r.Get("/overview", h.GetStorageOverview)
				r.Get("/service-data", h.GetServiceDataSizes)

				// SMB Shares
				r.Route("/smb", func(r chi.Router) {
					r.Get("/status", ext.GetSMBStatus)
					r.Get("/shares", ext.GetSMBShares)
					r.Get("/shares/{name}", ext.GetSMBShare)
					r.Post("/shares", ext.CreateSMBShare)
					r.Put("/shares/{name}", ext.UpdateSMBShare)
					r.Delete("/shares/{name}", ext.DeleteSMBShare)
				})

				// Disk Health (S.M.A.R.T.)
				r.Get("/health", ext.GetDiskHealth)
				r.Get("/health/{device}", ext.GetDiskHealthByDevice)
			})

			// Docker Services
			r.Route("/services", func(r chi.Router) {
				r.Get("/", h.GetServices)
				r.Get("/status", h.GetAllContainerStatus)
				r.Get("/categories", h.GetCategories)
				r.Get("/{name}", h.GetService)
				r.Get("/{name}/logs", h.GetServiceLogs)
				r.Get("/{name}/stats", h.GetServiceStats)
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
			})

			// ===========================================================
			// Extended APIs
			// ===========================================================

			// Logs
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

			// Backup
			r.Route("/backup", func(r chi.Router) {
				r.Get("/", ext.ListBackups)
				r.Get("/stats/summary", ext.GetBackupStats)
				r.Get("/{backup_id}", ext.GetBackup)
				r.Get("/{backup_id}/download", ext.DownloadBackup)
				r.Post("/create", ext.CreateBackup)
				r.Post("/quick", ext.QuickBackup)
				r.Post("/restore/{backup_id}", ext.RestoreBackup)
				r.Delete("/{backup_id}", ext.DeleteBackup)
			})

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
				r.Post("/apply-profile", ext.ApplyProfile)
				r.Post("/estimate", ext.EstimateResources)
			})

			// Monitoring
			r.Route("/monitoring", func(r chi.Router) {
				r.Get("/stats", ext.GetMonitoringStats)
				r.Get("/connections", wsHandlers.GetConnectionCount)
				r.Get("/history", ext.GetStatsHistory)
				r.Get("/alerts/thresholds", ext.GetAlertThresholds)
				r.Put("/alerts/thresholds", ext.SetAlertThresholds)
				r.Get("/alerts/current", ext.GetCurrentAlerts)
			})

			// Power/UPS
			r.Route("/power", func(r chi.Router) {
				r.Get("/status", ext.GetPowerStatus)
				r.Post("/charging", ext.SetCharging)
			})

			// Preferences
			r.Get("/preferences", ext.GetPreferences)
			r.Post("/preferences", ext.SetPreferences)

			// Favorites
			r.Get("/favorites", ext.GetFavorites)
			r.Post("/favorites/{name}", ext.AddFavorite)
			r.Delete("/favorites/{name}", ext.RemoveFavorite)
			r.Put("/favorites/{name}/toggle", ext.ToggleFavorite)

			// App Store
			r.Mount("/appstore", appStoreHandler.Routes())

			// Chat (AI Assistant)
			r.Mount("/chat", chatHandler.Routes())

			// Documentation (offline docs viewer)
			r.Mount("/documentation", docsHandler.Routes())

			// Unified Apps API (Sprint 3)
			if appsHandler != nil {
				r.Mount("/apps", appsHandler.Routes())
			}

			// Profiles API (Sprint 3)
			if profilesHandler != nil {
				r.Mount("/profiles", profilesHandler.Routes())
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

			// NOTE: Network routes are already defined in /network block above.
			// DO NOT add r.Mount("/network", ...) here - it causes duplicate route panic!
		})

		// Setup wizard routes (semi-public - accessible before full setup)
		r.Mount("/setup", setupHandler.Routes())
	})

	// Legacy API routes (without /v1 prefix for backward compatibility)
	r.Route("/api", func(r chi.Router) {
		r.Use(middleware.JWTAuth(cfg))

		// Preferences (matches Python API path)
		r.Get("/preferences", ext.GetPreferences)
		r.Post("/preferences", ext.SetPreferences)

		// Wizard (matches Python API path)
		r.Route("/wizard", func(r chi.Router) {
			r.Get("/profiles", ext.GetProfiles)
			r.Get("/services", ext.GetWizardServices)
			r.Get("/recommendations", ext.GetRecommendations)
			r.Post("/apply-profile", ext.ApplyProfile)
		})
	})

	// Start server
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	log.Printf("API listening on %s", addr)
	log.Printf("Documentation: http://%s/health", addr)

	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func initDB(db *sqlx.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		role TEXT DEFAULT 'user',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	
	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	
	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	
	CREATE TABLE IF NOT EXISTS service_states (
		name TEXT PRIMARY KEY,
		enabled BOOLEAN DEFAULT TRUE,
		reason TEXT,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`

	_, err := db.Exec(schema)
	if err != nil {
		return err
	}

	// Create default admin user if not exists
	var count int
	db.Get(&count, "SELECT COUNT(*) FROM users WHERE username = 'admin'")
	if count == 0 {
		// Generate hash for default password: cubeos
		defaultPassword := "cubeos"
		hash, err := bcrypt.GenerateFromPassword([]byte(defaultPassword), bcrypt.DefaultCost)
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
		log.Println("Created default admin user (password: cubeos)")
	}

	return nil
}

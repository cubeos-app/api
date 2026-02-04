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
	httpSwagger "github.com/swaggo/http-swagger"
	"golang.org/x/crypto/bcrypt"

	"cubeos-api/internal/config"
	"cubeos-api/internal/database"
	"cubeos-api/internal/hal"
	"cubeos-api/internal/handlers"
	"cubeos-api/internal/managers"
	"cubeos-api/internal/middleware"

	_ "cubeos-api/docs" // Import generated swagger docs
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

	// Create HAL-based handlers (Sprint 6)
	hardwareHandler := handlers.NewHardwareHandler(halClient)
	halStorageHandler := handlers.NewStorageHandler(halClient)
	communicationHandler := handlers.NewCommunicationHandler(halClient)
	mediaHandler := handlers.NewMediaHandler(halClient)
	halLogsHandler := handlers.NewLogsHandler(halClient)
	log.Printf("HAL handlers initialized (Hardware, Storage, Communication, Media, Logs)")

	// Create WebSocket manager and handlers
	wsManager := handlers.NewWSManager(systemMgr, networkMgr, monitoringMgr, docker)
	wsHandlers := handlers.NewWSHandlers(wsManager)

	// Create router
	r := chi.NewRouter()

	// Middleware
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)
	r.Use(chimw.RealIP)
	r.Use(chimw.RequestID)
	r.Use(chimw.Timeout(60 * time.Second))

	// CORS configuration
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Public routes
	r.Get("/health", h.Health)

	// WebSocket routes (public, auth via query param)
	r.Get("/ws/stats", wsHandlers.StatsWebSocket)
	r.Get("/ws/monitoring", wsHandlers.MonitoringWebSocket)

	// Swagger documentation
	r.Get("/api/v1/docs/*", httpSwagger.Handler(
		httpSwagger.URL("/api/v1/docs/doc.json"),
		httpSwagger.DeepLinking(true),
		httpSwagger.DocExpansion("none"),
		httpSwagger.DomID("swagger-ui"),
	))

	// API v1 routes
	r.Route("/api/v1", func(r chi.Router) {
		// Public auth routes
		r.Post("/auth/login", h.Login)

		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(middleware.JWTAuth(cfg))

			// Auth routes
			r.Route("/auth", func(r chi.Router) {
				r.Post("/logout", h.Logout)
				r.Post("/refresh", h.RefreshToken)
				r.Get("/me", h.GetMe)
				r.Post("/password", h.ChangePassword)
			})

			// System Info
			r.Route("/system", func(r chi.Router) {
				r.Get("/info", h.GetSystemInfo)
				r.Get("/stats", h.GetSystemStats)
				r.Get("/hostname", h.GetHostname)
				r.Post("/hostname", h.SetHostname)
				r.Get("/timezone", h.GetTimezone)
				r.Post("/timezone", h.SetTimezone)
				r.Get("/timezones", h.GetTimezones)
				r.Post("/reboot", h.Reboot)
				r.Post("/shutdown", h.Shutdown)
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

			// Storage (SMB Shares - legacy, unified in /mounts)
			r.Route("/storage", func(r chi.Router) {
				r.Get("/", h.GetStorage)
				r.Get("/mounts", h.GetMounts)
				r.Post("/mounts", h.AddMount)
				r.Delete("/mounts/{id}", h.RemoveMount)
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

			// Power/UPS (legacy)
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

			// ===========================================================
			// HAL-based Hardware APIs (Sprint 6)
			// ===========================================================

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
	log.Printf("Swagger UI: http://%s/api/v1/docs/index.html", addr)
	log.Printf("HAL endpoints: /hardware, /hal/storage, /communication, /media, /hal/logs")

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

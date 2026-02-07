// Package managers provides the Orchestrator for unified app management.
package managers

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"cubeos-api/internal/config"
	"cubeos-api/internal/models"
)

// Orchestrator coordinates all app operations through a unified interface.
// It is the single point of control for app lifecycle management.
type Orchestrator struct {
	db     *sql.DB
	cfg    *config.Config
	swarm  *SwarmManager
	docker *DockerManager
	npm    *NPMManager
	pihole *PiholeManager
	ports  *PortManager
	ctx    context.Context
	cancel context.CancelFunc
}

// OrchestratorConfig holds configuration for the Orchestrator
type OrchestratorConfig struct {
	DB           *sql.DB
	Config       *config.Config
	CoreappsPath string
	AppsPath     string
	PiholePath   string
	NPMConfigDir string
}

// NewOrchestrator creates a new Orchestrator instance
func NewOrchestrator(cfg OrchestratorConfig) (*Orchestrator, error) {
	if cfg.DB == nil {
		return nil, fmt.Errorf("database connection required")
	}
	if cfg.Config == nil {
		return nil, fmt.Errorf("config required")
	}

	ctx, cancel := context.WithCancel(context.Background())

	o := &Orchestrator{
		db:     cfg.DB,
		cfg:    cfg.Config,
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize SwarmManager
	var err error
	o.swarm, err = NewSwarmManager()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create swarm manager: %w", err)
	}

	// Initialize DockerManager
	o.docker, err = NewDockerManager(cfg.Config)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create docker manager: %w", err)
	}

	// Initialize NPMManager
	npmConfigDir := cfg.NPMConfigDir
	if npmConfigDir == "" {
		npmConfigDir = "/cubeos/coreapps/npm/appdata"
	}
	o.npm = NewNPMManager(cfg.Config, npmConfigDir)

	// Initialize PiholeManager
	piholePath := cfg.PiholePath
	if piholePath == "" {
		piholePath = "/cubeos/coreapps/pihole/appdata"
	}
	o.pihole = NewPiholeManager(cfg.Config, piholePath)

	// Initialize PortManager
	o.ports = NewPortManager(cfg.DB)

	return o, nil
}

// Close releases resources held by the Orchestrator
func (o *Orchestrator) Close() error {
	o.cancel()
	if o.docker != nil {
		o.docker.Close()
	}
	return nil
}

// =============================================================================
// App Lifecycle Operations
// =============================================================================

// InstallApp installs a new application.
// Database operations are wrapped in a transaction for atomicity.
func (o *Orchestrator) InstallApp(ctx context.Context, req models.InstallAppRequest) (*models.App, error) {
	// Validate app name
	name := strings.ToLower(strings.TrimSpace(req.Name))
	if name == "" {
		return nil, fmt.Errorf("app name is required")
	}
	if !isValidAppName(name) {
		return nil, fmt.Errorf("invalid app name: must be lowercase alphanumeric with hyphens")
	}

	// Check if app already exists
	existing, _ := o.GetApp(ctx, name)
	if existing != nil {
		return nil, fmt.Errorf("app %s already exists", name)
	}

	// Determine paths based on app type
	appType := models.AppTypeUser
	basePath := "/cubeos/apps"
	if req.Type != "" {
		appType = req.Type
	}
	if appType == models.AppTypeSystem || appType == models.AppTypePlatform {
		basePath = "/cubeos/coreapps"
	}

	composePath := filepath.Join(basePath, name, "appconfig", "docker-compose.yml")
	dataPath := filepath.Join(basePath, name, "appdata")

	// Determine deploy mode
	deployMode := models.DeployModeStack
	if req.DeployMode != "" {
		deployMode = req.DeployMode
	}
	// Force compose mode for host network services
	if name == "pihole" || name == "npm" {
		deployMode = models.DeployModeCompose
	}

	// Allocate port
	port, err := o.ports.AllocateUserPort()
	if err != nil {
		return nil, fmt.Errorf("failed to allocate port: %w", err)
	}

	// Create directories
	if err := os.MkdirAll(filepath.Dir(composePath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create app directory: %w", err)
	}
	if err := os.MkdirAll(dataPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	// Generate display name
	displayName := req.DisplayName
	if displayName == "" {
		displayName = toTitleCase(strings.ReplaceAll(name, "-", " "))
	}

	// Generate FQDN
	fqdn := fmt.Sprintf("%s.%s", name, o.cfg.Domain)

	// Begin transaction for all database inserts
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() // no-op after Commit

	result, err := tx.ExecContext(ctx, `
		INSERT INTO apps (name, display_name, description, type, category, source, 
			compose_path, data_path, enabled, deploy_mode)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, name, displayName, req.Description, appType, req.Category, req.Source,
		composePath, dataPath, true, deployMode)
	if err != nil {
		return nil, fmt.Errorf("failed to insert app: %w", err)
	}

	appID, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get app ID: %w", err)
	}

	// Insert port allocation
	_, err = tx.ExecContext(ctx, `
		INSERT INTO port_allocations (app_id, port, protocol, description, is_primary)
		VALUES (?, ?, 'tcp', 'Web UI', TRUE)
	`, appID, port)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate port: %w", err)
	}

	// Insert FQDN
	_, err = tx.ExecContext(ctx, `
		INSERT INTO fqdns (app_id, fqdn, subdomain, backend_port)
		VALUES (?, ?, ?, ?)
	`, appID, fqdn, name, port)
	if err != nil {
		return nil, fmt.Errorf("failed to register FQDN: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit app install: %w", err)
	}

	// Deploy the app (outside transaction — rollback DB on failure)
	if err := o.deployApp(ctx, name, composePath, deployMode); err != nil {
		// Best-effort rollback: remove the committed DB rows
		if _, dbErr := o.db.ExecContext(ctx, "DELETE FROM apps WHERE id = ?", appID); dbErr != nil {
			log.Error().Err(dbErr).Str("app", name).Msg("Failed to rollback app row after deploy failure")
		}
		return nil, fmt.Errorf("failed to deploy app: %w", err)
	}

	// Register DNS entry with Pi-hole (non-fatal)
	if err := o.pihole.AddEntry(fqdn, models.DefaultGatewayIP); err != nil {
		log.Warn().Err(err).Str("fqdn", fqdn).Msg("Failed to add DNS entry")
	}

	// Create NPM proxy host (non-fatal)
	proxyHost := &NPMProxyHostExtended{
		DomainNames:           []string{fqdn},
		ForwardScheme:         "http",
		ForwardHost:           models.DefaultGatewayIP,
		ForwardPort:           port,
		BlockExploits:         true,
		AllowWebsocketUpgrade: true,
		AccessListID:          0,
		CertificateID:         0,
		AdvancedConfig:        "",
		Meta:                  NPMMeta{},
	}
	if _, err := o.npm.CreateProxyHost(proxyHost); err != nil {
		log.Warn().Err(err).Str("fqdn", fqdn).Msg("Failed to create NPM proxy")
	}

	// Return the created app
	return o.GetApp(ctx, name)
}

// UninstallApp removes an application
func (o *Orchestrator) UninstallApp(ctx context.Context, name string, keepData bool) error {
	app, err := o.GetApp(ctx, name)
	if err != nil {
		return fmt.Errorf("app not found: %w", err)
	}

	// Prevent uninstalling protected system apps
	if app.IsProtected() {
		return fmt.Errorf("cannot uninstall protected system app: %s", name)
	}

	// Stop the app first
	if err := o.StopApp(ctx, name); err != nil {
		log.Warn().Err(err).Str("app", name).Msg("Failed to stop app during uninstall")
	}

	// Remove from Swarm/Docker
	if app.UsesSwarm() {
		if err := o.swarm.RemoveStack(name); err != nil {
			log.Warn().Err(err).Str("app", name).Msg("Failed to remove stack during uninstall")
		}
	} else {
		// Stop and remove container
		o.docker.StopContainer(ctx, "cubeos-"+name, 10)
	}

	// Remove NPM proxy host
	if proxyHost, err := o.npm.FindProxyHostByDomain(app.GetPrimaryFQDN()); err == nil && proxyHost != nil {
		if err := o.npm.DeleteProxyHost(proxyHost.ID); err != nil {
			log.Warn().Err(err).Str("app", name).Msg("Failed to delete NPM proxy during uninstall")
		}
	}

	// Remove DNS entry
	if fqdn := app.GetPrimaryFQDN(); fqdn != "" {
		if err := o.pihole.RemoveEntry(fqdn); err != nil {
			log.Warn().Err(err).Str("fqdn", fqdn).Msg("Failed to remove DNS entry during uninstall")
		}
	}

	// Delete from database (cascades to ports and fqdns)
	_, err = o.db.ExecContext(ctx, "DELETE FROM apps WHERE id = ?", app.ID)
	if err != nil {
		return fmt.Errorf("failed to delete app from database: %w", err)
	}

	// Optionally remove data
	if !keepData && app.DataPath != "" {
		if err := os.RemoveAll(app.DataPath); err != nil {
			log.Warn().Err(err).Str("path", app.DataPath).Msg("Failed to remove data directory during uninstall")
		}
	}

	return nil
}

// StartApp starts an application
func (o *Orchestrator) StartApp(ctx context.Context, name string) error {
	app, err := o.GetApp(ctx, name)
	if err != nil {
		return fmt.Errorf("app not found: %w", err)
	}

	if app.UsesSwarm() {
		// Deploy/update the stack
		return o.swarm.DeployStack(name, app.ComposePath)
	}

	// Start container via docker compose
	return o.docker.StartContainer(ctx, "cubeos-"+name)
}

// StopApp stops an application
func (o *Orchestrator) StopApp(ctx context.Context, name string) error {
	app, err := o.GetApp(ctx, name)
	if err != nil {
		return fmt.Errorf("app not found: %w", err)
	}

	if app.UsesSwarm() {
		// Scale to 0 replicas instead of removing stack
		return o.swarm.ScaleService(name+"_"+name, 0)
	}

	return o.docker.StopContainer(ctx, "cubeos-"+name, 10)
}

// RestartApp restarts an application
func (o *Orchestrator) RestartApp(ctx context.Context, name string) error {
	app, err := o.GetApp(ctx, name)
	if err != nil {
		return fmt.Errorf("app not found: %w", err)
	}

	if app.UsesSwarm() {
		// Force service restart
		return o.swarm.RestartService(name + "_" + name)
	}

	return o.docker.RestartContainer(ctx, "cubeos-"+name, 10)
}

// EnableApp marks an app to start on boot
func (o *Orchestrator) EnableApp(ctx context.Context, name string) error {
	// Verify app exists
	if _, err := o.GetApp(ctx, name); err != nil {
		return fmt.Errorf("app not found: %w", err)
	}

	_, err := o.db.ExecContext(ctx, `
		UPDATE apps SET enabled = TRUE, updated_at = CURRENT_TIMESTAMP 
		WHERE name = ?
	`, name)
	return err
}

// DisableApp marks an app to not start on boot
func (o *Orchestrator) DisableApp(ctx context.Context, name string) error {
	app, err := o.GetApp(ctx, name)
	if err != nil {
		return err
	}

	// Prevent disabling protected system apps
	if app.IsProtected() {
		return fmt.Errorf("cannot disable protected system app: %s", name)
	}

	_, err = o.db.ExecContext(ctx, `
		UPDATE apps SET enabled = FALSE, updated_at = CURRENT_TIMESTAMP 
		WHERE name = ?
	`, name)
	return err
}

// =============================================================================
// Query Operations
// =============================================================================

// GetApp retrieves a single app by name with all related data
func (o *Orchestrator) GetApp(ctx context.Context, name string) (*models.App, error) {
	var app models.App
	err := o.db.QueryRowContext(ctx, `
		SELECT id, name, display_name, description, type, category, source, store_id,
			compose_path, data_path, enabled, tor_enabled, vpn_enabled,
			deploy_mode, icon_url, version, homepage, created_at, updated_at
		FROM apps WHERE name = ?
	`, name).Scan(
		&app.ID, &app.Name, &app.DisplayName, &app.Description, &app.Type,
		&app.Category, &app.Source, &app.StoreID, &app.ComposePath, &app.DataPath,
		&app.Enabled, &app.TorEnabled, &app.VPNEnabled,
		&app.DeployMode, &app.IconURL, &app.Version, &app.Homepage,
		&app.CreatedAt, &app.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("app not found: %s", name)
	}
	if err != nil {
		return nil, err
	}

	// Load related data
	if err := o.loadAppRelations(ctx, &app); err != nil {
		return nil, err
	}

	// Get runtime status
	app.Status = o.getAppStatus(ctx, &app)

	return &app, nil
}

// ListApps retrieves all apps with optional filtering
func (o *Orchestrator) ListApps(ctx context.Context, filter *models.AppFilter) ([]*models.App, error) {
	query := `
		SELECT id, name, display_name, description, type, category, source, store_id,
			compose_path, data_path, enabled, tor_enabled, vpn_enabled,
			deploy_mode, icon_url, version, homepage, created_at, updated_at
		FROM apps WHERE 1=1
	`
	var args []interface{}

	if filter != nil {
		if filter.Type != "" {
			query += " AND type = ?"
			args = append(args, filter.Type)
		}
		if filter.Enabled != nil {
			query += " AND enabled = ?"
			args = append(args, *filter.Enabled)
		}
	}

	query += " ORDER BY type, name"

	rows, err := o.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var apps []*models.App
	for rows.Next() {
		var app models.App
		err := rows.Scan(
			&app.ID, &app.Name, &app.DisplayName, &app.Description, &app.Type,
			&app.Category, &app.Source, &app.StoreID, &app.ComposePath, &app.DataPath,
			&app.Enabled, &app.TorEnabled, &app.VPNEnabled,
			&app.DeployMode, &app.IconURL, &app.Version, &app.Homepage,
			&app.CreatedAt, &app.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		// Get runtime status
		app.Status = o.getAppStatus(ctx, &app)

		apps = append(apps, &app)
	}

	return apps, rows.Err()
}

// =============================================================================
// Reconciliation Operations
// =============================================================================

// ReconcileState ensures running state matches desired state
// Called on boot to recover from power loss
func (o *Orchestrator) ReconcileState(ctx context.Context) error {
	apps, err := o.ListApps(ctx, &models.AppFilter{Enabled: boolPtr(true)})
	if err != nil {
		return fmt.Errorf("failed to list enabled apps: %w", err)
	}

	var errors []string
	for _, app := range apps {
		if app.Status == nil || !app.Status.Running {
			log.Info().Str("app", app.Name).Msg("Reconciling: starting app")
			if err := o.StartApp(ctx, app.Name); err != nil {
				errors = append(errors, fmt.Sprintf("%s: %v", app.Name, err))
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("reconciliation errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

// SeedSystemApps creates database entries for core system apps
// Called on first boot to populate the database
func (o *Orchestrator) SeedSystemApps(ctx context.Context) error {
	systemApps := []struct {
		name        string
		displayName string
		appType     models.AppType
		port        int
		deployMode  models.DeployMode
	}{
		{"pihole", "Pi-hole", models.AppTypeSystem, 6001, models.DeployModeCompose},
		{"npm", "Nginx Proxy Manager", models.AppTypeSystem, 6000, models.DeployModeCompose},
		{"registry", "Docker Registry", models.AppTypeSystem, 5000, models.DeployModeStack},
		{"cubeos-api", "CubeOS API", models.AppTypePlatform, 6010, models.DeployModeStack},
		{"cubeos-dashboard", "CubeOS Dashboard", models.AppTypePlatform, 6011, models.DeployModeStack},
		{"dozzle", "Dozzle", models.AppTypePlatform, 6012, models.DeployModeStack},
		{"ollama", "Ollama", models.AppTypeAI, 6030, models.DeployModeStack},
		{"chromadb", "ChromaDB", models.AppTypeAI, 6031, models.DeployModeStack},
	}

	for _, sa := range systemApps {
		// Check if already exists
		var count int
		if err := o.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM apps WHERE name = ?", sa.name).Scan(&count); err != nil {
			return fmt.Errorf("failed to check existence of %s: %w", sa.name, err)
		}
		if count > 0 {
			continue
		}

		composePath := fmt.Sprintf("/cubeos/coreapps/%s/appconfig/docker-compose.yml", sa.name)
		dataPath := fmt.Sprintf("/cubeos/coreapps/%s/appdata", sa.name)

		result, err := o.db.ExecContext(ctx, `
			INSERT INTO apps (name, display_name, type, compose_path, data_path, enabled, deploy_mode)
			VALUES (?, ?, ?, ?, ?, TRUE, ?)
		`, sa.name, sa.displayName, sa.appType, composePath, dataPath, sa.deployMode)
		if err != nil {
			return fmt.Errorf("failed to seed %s: %w", sa.name, err)
		}

		appID, err := result.LastInsertId()
		if err != nil {
			return fmt.Errorf("failed to get ID for %s: %w", sa.name, err)
		}

		// Add port allocation
		if _, err := o.db.ExecContext(ctx, `
			INSERT INTO port_allocations (app_id, port, protocol, description, is_primary)
			VALUES (?, ?, 'tcp', 'Web UI', TRUE)
		`, appID, sa.port); err != nil {
			return fmt.Errorf("failed to allocate port for %s: %w", sa.name, err)
		}

		// Add FQDN
		fqdn := fmt.Sprintf("%s.%s", sa.name, o.cfg.Domain)
		if _, err := o.db.ExecContext(ctx, `
			INSERT INTO fqdns (app_id, fqdn, subdomain, backend_port)
			VALUES (?, ?, ?, ?)
		`, appID, fqdn, sa.name, sa.port); err != nil {
			return fmt.Errorf("failed to register FQDN for %s: %w", sa.name, err)
		}
	}

	return nil
}

// =============================================================================
// Helper Functions
// =============================================================================

func (o *Orchestrator) deployApp(ctx context.Context, name, composePath string, mode models.DeployMode) error {
	if mode == models.DeployModeStack {
		return o.swarm.DeployStack(name, composePath)
	}

	// Compose mode: no-op here. Host-network services (pihole, npm) are managed
	// externally via systemd or docker-compose directly on the host. The orchestrator
	// only tracks their state in the database; actual lifecycle is handled outside Swarm.
	log.Debug().Str("app", name).Msg("Compose mode deploy is a no-op — managed externally")
	return nil
}

func (o *Orchestrator) getAppStatus(ctx context.Context, app *models.App) *models.AppStatus {
	status := &models.AppStatus{
		Running: false,
		Health:  "unknown",
	}

	if app.UsesSwarm() {
		// Get status from Swarm with timeout
		svcStatus, err := o.swarm.GetServiceStatus(app.Name + "_" + app.Name)
		if err == nil && svcStatus != nil {
			status.Running = svcStatus.Running
			status.Replicas = svcStatus.Replicas
			status.Health = svcStatus.Health
			if !status.Running {
				status.Health = "stopped"
			}
		}
	} else {
		// Get status from Docker with timeout context
		containerName := "cubeos-" + app.Name
		timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		containerStatus, err := o.docker.GetContainerStatus(timeoutCtx, containerName)
		if err == nil {
			status.Running = containerStatus == "running"
			if status.Running {
				if strings.Contains(containerStatus, "healthy") {
					status.Health = "healthy"
				} else if strings.Contains(containerStatus, "unhealthy") {
					status.Health = "unhealthy"
				} else {
					status.Health = "running"
				}
			} else {
				status.Health = "stopped"
			}
			status.Replicas = "1/1"
			if !status.Running {
				status.Replicas = "0/1"
			}
		}
	}

	return status
}

func (o *Orchestrator) loadAppRelations(ctx context.Context, app *models.App) error {
	// Load ports — close rows explicitly before second query to free SQLite connection
	rows, err := o.db.QueryContext(ctx, `
		SELECT id, app_id, port, protocol, description, is_primary
		FROM port_allocations WHERE app_id = ?
	`, app.ID)
	if err != nil {
		return err
	}

	for rows.Next() {
		var port models.Port
		if err := rows.Scan(&port.ID, &port.AppID, &port.Port, &port.Protocol,
			&port.Description, &port.IsPrimary); err != nil {
			rows.Close()
			return err
		}
		app.Ports = append(app.Ports, port)
	}
	rows.Close()

	if err := rows.Err(); err != nil {
		return err
	}

	// Load FQDNs — connection is now free
	fqdnRows, err := o.db.QueryContext(ctx, `
		SELECT id, app_id, fqdn, subdomain, backend_port, ssl_enabled
		FROM fqdns WHERE app_id = ?
	`, app.ID)
	if err != nil {
		return err
	}
	defer fqdnRows.Close()

	for fqdnRows.Next() {
		var fqdn models.FQDN
		if err := fqdnRows.Scan(&fqdn.ID, &fqdn.AppID, &fqdn.FQDN, &fqdn.Subdomain,
			&fqdn.BackendPort, &fqdn.SSLEnabled); err != nil {
			return err
		}
		app.FQDNs = append(app.FQDNs, fqdn)
	}

	return fqdnRows.Err()
}

// isValidAppName checks if an app name is valid (lowercase alphanumeric with hyphens)
func isValidAppName(name string) bool {
	if len(name) == 0 || len(name) > 63 {
		return false
	}
	for i, c := range name {
		if c >= 'a' && c <= 'z' {
			continue
		}
		if c >= '0' && c <= '9' {
			continue
		}
		if c == '-' && i > 0 && i < len(name)-1 {
			continue
		}
		return false
	}
	return true
}

// toTitleCase capitalizes the first letter of each word.
// Replaces deprecated strings.Title without requiring golang.org/x/text.
func toTitleCase(s string) string {
	words := strings.Fields(s)
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

func boolPtr(b bool) *bool {
	return &b
}

// =============================================================================
// Logs Operations
// =============================================================================

// GetAppLogs retrieves logs for an application.
func (o *Orchestrator) GetAppLogs(ctx context.Context, name string, lines int, since time.Time) ([]string, error) {
	app, err := o.GetApp(ctx, name)
	if err != nil {
		return nil, err
	}

	if app.UsesSwarm() {
		// Get logs from Swarm service
		return o.swarm.GetServiceLogs(name+"_"+name, lines)
	}

	// Get logs from docker container
	// Convert time.Time to RFC3339 string for docker API
	sinceStr := ""
	if !since.IsZero() {
		sinceStr = since.Format(time.RFC3339)
	}
	logsStr, err := o.docker.GetContainerLogs(ctx, "cubeos-"+name, lines, sinceStr)
	if err != nil {
		return nil, err
	}

	// Split log string into lines
	if logsStr == "" {
		return []string{}, nil
	}
	return strings.Split(strings.TrimSuffix(logsStr, "\n"), "\n"), nil
}

// =============================================================================
// Routing Operations (Tor/VPN)
// =============================================================================

// SetAppTor enables or disables Tor routing for an app.
func (o *Orchestrator) SetAppTor(ctx context.Context, name string, enabled bool) error {
	app, err := o.GetApp(ctx, name)
	if err != nil {
		return err
	}

	// Prevent modifying protected system apps
	if app.IsProtected() {
		return fmt.Errorf("cannot modify routing for protected system app: %s", name)
	}

	_, err = o.db.ExecContext(ctx, `
		UPDATE apps SET tor_enabled = ?, updated_at = CURRENT_TIMESTAMP 
		WHERE name = ?
	`, enabled, name)
	if err != nil {
		return fmt.Errorf("failed to update tor setting: %w", err)
	}

	// TODO: Actually configure Tor proxy for this app's network
	// This will be implemented when Tor coreapp is fully integrated

	return nil
}

// SetAppVPN enables or disables VPN routing for an app.
func (o *Orchestrator) SetAppVPN(ctx context.Context, name string, enabled bool) error {
	app, err := o.GetApp(ctx, name)
	if err != nil {
		return err
	}

	// Prevent modifying protected system apps
	if app.IsProtected() {
		return fmt.Errorf("cannot modify routing for protected system app: %s", name)
	}

	_, err = o.db.ExecContext(ctx, `
		UPDATE apps SET vpn_enabled = ?, updated_at = CURRENT_TIMESTAMP 
		WHERE name = ?
	`, enabled, name)
	if err != nil {
		return fmt.Errorf("failed to update vpn setting: %w", err)
	}

	// TODO: Actually configure VPN routing for this app's network
	// This will be implemented when WireGuard/OpenVPN coreapps are fully integrated

	return nil
}

// =============================================================================
// Profile Operations
// =============================================================================

// ListProfiles returns all profiles and the currently active profile name.
// FIX: Close rows before loading profile apps to avoid SQLite deadlock with MaxOpenConns(1)
func (o *Orchestrator) ListProfiles(ctx context.Context) ([]models.Profile, string, error) {
	rows, err := o.db.QueryContext(ctx, `
		SELECT id, name, display_name, description, is_active, is_system, 
			created_at, updated_at
		FROM profiles
		ORDER BY is_system DESC, name ASC
	`)
	if err != nil {
		return nil, "", err
	}

	var profiles []models.Profile
	var activeProfile string

	// First pass: collect all profiles (keep rows open only for scanning)
	for rows.Next() {
		var p models.Profile
		if err := rows.Scan(&p.ID, &p.Name, &p.DisplayName, &p.Description,
			&p.IsActive, &p.IsSystem, &p.CreatedAt, &p.UpdatedAt); err != nil {
			rows.Close()
			return nil, "", err
		}

		if p.IsActive {
			activeProfile = p.Name
		}

		profiles = append(profiles, p)
	}

	// Close rows BEFORE loading apps to free the connection
	rows.Close()

	if err := rows.Err(); err != nil {
		return nil, "", err
	}

	// Second pass: load apps for each profile (connection is now free)
	for i := range profiles {
		if err := o.loadProfileApps(ctx, &profiles[i]); err != nil {
			return nil, "", err
		}
	}

	return profiles, activeProfile, nil
}

// GetProfile retrieves a single profile by name.
func (o *Orchestrator) GetProfile(ctx context.Context, name string) (*models.Profile, error) {
	var p models.Profile
	err := o.db.QueryRowContext(ctx, `
		SELECT id, name, display_name, description, is_active, is_system,
			created_at, updated_at
		FROM profiles WHERE name = ?
	`, name).Scan(&p.ID, &p.Name, &p.DisplayName, &p.Description,
		&p.IsActive, &p.IsSystem, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("profile not found: %s", name)
	}

	if err := o.loadProfileApps(ctx, &p); err != nil {
		return nil, err
	}

	return &p, nil
}

// CreateProfile creates a new custom profile.
func (o *Orchestrator) CreateProfile(ctx context.Context, req models.CreateProfileRequest) (*models.Profile, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("profile name is required")
	}

	displayName := req.DisplayName
	if displayName == "" {
		displayName = req.Name
	}

	result, err := o.db.ExecContext(ctx, `
		INSERT INTO profiles (name, display_name, description, is_active, is_system)
		VALUES (?, ?, ?, FALSE, FALSE)
	`, req.Name, displayName, req.Description)
	if err != nil {
		return nil, err
	}

	id, _ := result.LastInsertId()

	return &models.Profile{
		ID:          id,
		Name:        req.Name,
		DisplayName: displayName,
		Description: req.Description,
		IsActive:    false,
		IsSystem:    false,
	}, nil
}

// ApplyProfile makes a profile active, starting/stopping apps as needed.
func (o *Orchestrator) ApplyProfile(ctx context.Context, name string) (*models.ApplyProfileResponse, error) {
	profile, err := o.GetProfile(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("profile not found: %s", name)
	}

	var started, stopped []string

	// Get apps to enable from this profile
	enabledApps := profile.GetEnabledApps()

	// Get all apps
	allApps, err := o.ListApps(ctx, nil)
	if err != nil {
		return nil, err
	}

	// Stop apps that should be disabled
	for _, app := range allApps {
		shouldBeEnabled := false
		for _, enabledName := range enabledApps {
			if app.Name == enabledName {
				shouldBeEnabled = true
				break
			}
		}

		if !shouldBeEnabled && !app.IsProtected() && app.Status != nil && app.Status.Running {
			if err := o.StopApp(ctx, app.Name); err != nil {
				log.Warn().Err(err).Str("app", app.Name).Msg("Failed to stop app during profile apply")
			} else {
				stopped = append(stopped, app.Name)
			}
		}
	}

	// Start apps that should be enabled
	for _, appName := range enabledApps {
		app, err := o.GetApp(ctx, appName)
		if err != nil {
			continue // App not installed
		}
		if app.Status == nil || !app.Status.Running {
			if err := o.StartApp(ctx, appName); err != nil {
				log.Warn().Err(err).Str("app", appName).Msg("Failed to start app during profile apply")
			} else {
				started = append(started, appName)
			}
		}
	}

	// Update active profile in database (single statement with CASE)
	_, err = o.db.ExecContext(ctx, `
		UPDATE profiles SET 
			is_active = (name = ?),
			updated_at = CASE WHEN name = ? THEN CURRENT_TIMESTAMP ELSE updated_at END
	`, name, name)
	if err != nil {
		return nil, err
	}

	return &models.ApplyProfileResponse{
		Profile: name,
		Started: started,
		Stopped: stopped,
		Success: true,
		Message: fmt.Sprintf("Profile '%s' applied successfully", name),
	}, nil
}

// SetProfileApp enables or disables an app within a profile.
// Uses INSERT OR REPLACE to handle both new associations and updates.
func (o *Orchestrator) SetProfileApp(ctx context.Context, profileID, appID int64, enabled bool) error {
	_, err := o.db.ExecContext(ctx, `
		INSERT INTO profile_apps (profile_id, app_id, enabled)
		VALUES (?, ?, ?)
		ON CONFLICT (profile_id, app_id) DO UPDATE SET enabled = excluded.enabled
	`, profileID, appID, enabled)
	return err
}

// loadProfileApps loads the apps associated with a profile.
func (o *Orchestrator) loadProfileApps(ctx context.Context, profile *models.Profile) error {
	rows, err := o.db.QueryContext(ctx, `
		SELECT pa.profile_id, pa.app_id, a.name, pa.enabled
		FROM profile_apps pa
		JOIN apps a ON pa.app_id = a.id
		WHERE pa.profile_id = ?
	`, profile.ID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var pa models.ProfileApp
		if err := rows.Scan(&pa.ProfileID, &pa.AppID, &pa.AppName, &pa.Enabled); err != nil {
			return err
		}
		profile.Apps = append(profile.Apps, pa)
	}

	return rows.Err()
}

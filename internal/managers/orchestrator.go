// Package managers provides the Orchestrator for unified app management.
package managers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"cubeos-api/internal/config"
	"cubeos-api/internal/hal"
	"cubeos-api/internal/models"
)

// Orchestrator coordinates all app operations through a unified interface.
// It is the single point of control for app lifecycle management.
type Orchestrator struct {
	db             *sql.DB
	cfg            *config.Config
	swarm          *SwarmManager
	docker         *DockerManager
	npm            *NPMManager
	pihole         *PiholeManager
	ports          *PortManager
	hal            *hal.Client
	registryURL    string
	registryClient *http.Client
	ctx            context.Context
	cancel         context.CancelFunc
}

// OrchestratorConfig holds configuration for the Orchestrator
type OrchestratorConfig struct {
	DB           *sql.DB
	Config       *config.Config
	CoreappsPath string
	AppsPath     string
	PiholePath   string
	NPMConfigDir string
	HALClient    *hal.Client
	RegistryURL  string        // Local Docker registry URL (e.g. http://10.42.24.1:5000)
	SwarmManager *SwarmManager // Optional: shared instance; if nil, one is created internally
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
		db:          cfg.DB,
		cfg:         cfg.Config,
		hal:         cfg.HALClient,
		registryURL: cfg.RegistryURL,
		registryClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize SwarmManager (use provided instance or create new)
	var err error
	if cfg.SwarmManager != nil {
		o.swarm = cfg.SwarmManager
	} else {
		o.swarm, err = NewSwarmManager()
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to create swarm manager: %w", err)
		}
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

	// Initialize PortManager with triple-source validation (DB + Swarm + HAL)
	o.ports = NewPortManager(cfg.DB, o.swarm, cfg.HALClient)

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

	// Register DNS entry with Pi-hole (non-fatal) and reload (B116)
	if err := o.pihole.AddEntry(fqdn, models.DefaultGatewayIP); err != nil {
		log.Warn().Err(err).Str("fqdn", fqdn).Msg("Failed to add DNS entry")
	} else {
		if err := o.pihole.ReloadDNS(); err != nil {
			log.Warn().Err(err).Msg("Failed to reload Pi-hole DNS after install")
		}
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

// InstallFromRegistryWithProgress installs a registry image with SSE progress tracking.
// This creates the compose file from the image/tag, allocates a port, sets up DNS/proxy,
// and deploys as a Swarm stack — emitting progress events to the provided Job throughout.
func (o *Orchestrator) InstallFromRegistryWithProgress(ctx context.Context, req models.InstallAppRequest, job *Job) (*models.App, error) {
	name := strings.ToLower(strings.TrimSpace(req.Name))
	if name == "" {
		return nil, fmt.Errorf("app name is required")
	}
	if !isValidAppName(name) {
		return nil, fmt.Errorf("invalid app name: must be lowercase alphanumeric with hyphens")
	}
	if req.Image == "" {
		return nil, fmt.Errorf("image is required for registry install")
	}
	if req.Tag == "" {
		req.Tag = "latest"
	}

	// Check if app already exists
	existing, _ := o.GetApp(ctx, name)
	if existing != nil {
		return nil, fmt.Errorf("app %s already exists", name)
	}

	job.Emit("setup", 10, "Creating app directories")

	// Create app directories
	appBase := filepath.Join("/cubeos/apps", name)
	appConfig := filepath.Join(appBase, "appconfig")
	appData := filepath.Join(appBase, "appdata")
	if err := os.MkdirAll(appConfig, 0755); err != nil {
		return nil, fmt.Errorf("failed to create app directory: %w", err)
	}
	if err := os.MkdirAll(appData, 0777); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}
	os.Chmod(appData, 0777) // Explicit chmod to override umask

	job.Emit("port", 20, "Allocating port")

	// Allocate port
	allocatedPort, err := o.ports.AllocateUserPort()
	if err != nil {
		os.RemoveAll(appBase)
		return nil, fmt.Errorf("failed to allocate port: %w", err)
	}

	job.Emit("port", 25, fmt.Sprintf("Allocated port %d", allocatedPort))

	// Detect container port from image EXPOSE directives via registry manifest
	containerPort := allocatedPort
	job.Emit("manifest", 30, "Detecting container EXPOSE port")
	if detected := o.detectContainerPort(req.Image, req.Tag); detected > 0 {
		containerPort = detected
		log.Info().Str("image", req.Image).Int("port", detected).Msg("detected container EXPOSE port from registry manifest")
	}

	job.Emit("compose", 35, "Generating Docker config")

	// Build local registry image reference
	fullImage := fmt.Sprintf("localhost:5000/%s:%s", req.Image, req.Tag)

	// Generate docker-compose.yml
	compose := fmt.Sprintf(`version: "3.8"
services:
  %s:
    image: %s
    ports:
      - target: %d
        published: %d
        mode: ingress
    deploy:
      replicas: 1
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
    volumes:
      - %s:/data
`, name, fullImage, containerPort, allocatedPort, appData)

	composePath := filepath.Join(appConfig, "docker-compose.yml")
	if err := os.WriteFile(composePath, []byte(compose), 0644); err != nil {
		os.RemoveAll(appBase)
		return nil, fmt.Errorf("failed to write compose file: %w", err)
	}

	// Pre-create bind mount directories
	preCreateBindMounts(compose)

	job.Emit("database", 40, "Saving to database")

	// Generate display name and FQDN
	displayName := req.DisplayName
	if displayName == "" {
		displayName = toTitleCase(strings.ReplaceAll(name, "-", " "))
	}
	fqdn := fmt.Sprintf("%s.%s", name, o.cfg.Domain)

	// Database transaction: apps + port_allocations + fqdns
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		os.RemoveAll(appBase)
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, `
		INSERT INTO apps (name, display_name, description, type, category, source, 
			compose_path, data_path, enabled, deploy_mode)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, name, displayName, req.Description, models.AppTypeUser, "user", models.AppSourceRegistry,
		composePath, appData, true, models.DeployModeStack)
	if err != nil {
		os.RemoveAll(appBase)
		return nil, fmt.Errorf("failed to insert app: %w", err)
	}

	appID, err := result.LastInsertId()
	if err != nil {
		os.RemoveAll(appBase)
		return nil, fmt.Errorf("failed to get app ID: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO port_allocations (app_id, port, protocol, description, is_primary)
		VALUES (?, ?, 'tcp', 'Web UI', TRUE)
	`, appID, allocatedPort)
	if err != nil {
		os.RemoveAll(appBase)
		return nil, fmt.Errorf("failed to allocate port: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO fqdns (app_id, fqdn, subdomain, backend_port)
		VALUES (?, ?, ?, ?)
	`, appID, fqdn, name, allocatedPort)
	if err != nil {
		os.RemoveAll(appBase)
		return nil, fmt.Errorf("failed to register FQDN: %w", err)
	}

	if err := tx.Commit(); err != nil {
		os.RemoveAll(appBase)
		return nil, fmt.Errorf("failed to commit app install: %w", err)
	}

	job.Emit("deploy", 50, "Deploying Swarm stack")

	// Deploy as Swarm stack
	deployCtx, deployCancel := context.WithTimeout(ctx, 3*time.Minute)
	defer deployCancel()

	deployCmd := exec.CommandContext(deployCtx, "docker", "stack", "deploy",
		"-c", composePath,
		"--resolve-image=never",
		name,
	)
	deployCmd.Dir = appConfig
	if output, deployErr := deployCmd.CombinedOutput(); deployErr != nil {
		// Rollback DB on deploy failure
		if _, dbErr := o.db.ExecContext(ctx, "DELETE FROM apps WHERE id = ?", appID); dbErr != nil {
			log.Error().Err(dbErr).Str("app", name).Msg("Failed to rollback app row after deploy failure")
		}
		os.RemoveAll(appBase)
		return nil, fmt.Errorf("stack deploy failed: %s", string(output))
	}

	job.Emit("deploy", 70, "Stack deployed, configuring network")

	// DNS entry (non-fatal)
	job.Emit("dns", 80, "Configuring Pi-hole DNS")
	if err := o.pihole.AddEntry(fqdn, models.DefaultGatewayIP); err != nil {
		log.Warn().Err(err).Str("fqdn", fqdn).Msg("Failed to add DNS entry")
	} else {
		if err := o.pihole.ReloadDNS(); err != nil {
			log.Warn().Err(err).Msg("Failed to reload Pi-hole DNS after install")
		}
	}

	// NPM proxy host (non-fatal)
	job.Emit("proxy", 90, "Setting up reverse proxy")
	proxyHost := &NPMProxyHostExtended{
		DomainNames:           []string{fqdn},
		ForwardScheme:         "http",
		ForwardHost:           models.DefaultGatewayIP,
		ForwardPort:           allocatedPort,
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

	return o.GetApp(ctx, name)
}

// detectContainerPort queries the local Docker registry to find the EXPOSE port
// from an image's config. Returns 0 if detection fails (caller should use allocated port).
func (o *Orchestrator) detectContainerPort(image, tag string) int {
	if o.registryURL == "" || o.registryClient == nil {
		return 0
	}

	// Fetch the image manifest to get the config digest
	manifestURL := fmt.Sprintf("%s/v2/%s/manifests/%s", o.registryURL, image, tag)
	req, err := http.NewRequest("GET", manifestURL, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")

	resp, err := o.registryClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return 0
	}
	defer resp.Body.Close()

	var manifest struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil || manifest.Config.Digest == "" {
		return 0
	}

	// Fetch the image config blob to find ExposedPorts
	blobURL := fmt.Sprintf("%s/v2/%s/blobs/%s", o.registryURL, image, manifest.Config.Digest)
	blobResp, err := o.registryClient.Get(blobURL)
	if err != nil || blobResp.StatusCode != http.StatusOK {
		return 0
	}
	defer blobResp.Body.Close()

	var imgConfig struct {
		Config struct {
			ExposedPorts map[string]struct{} `json:"ExposedPorts"`
		} `json:"config"`
	}
	if err := json.NewDecoder(blobResp.Body).Decode(&imgConfig); err != nil {
		return 0
	}

	// Return first exposed port
	for portSpec := range imgConfig.Config.ExposedPorts {
		parts := strings.SplitN(portSpec, "/", 2)
		if port, err := strconv.Atoi(parts[0]); err == nil && port > 0 {
			return port
		}
	}
	return 0
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

	// Remove DNS entry and reload Pi-hole so removal takes effect immediately (B116)
	if fqdn := app.GetPrimaryFQDN(); fqdn != "" {
		if err := o.pihole.RemoveEntry(fqdn); err != nil {
			log.Warn().Err(err).Str("fqdn", fqdn).Msg("Failed to remove DNS entry during uninstall")
		} else {
			if err := o.pihole.ReloadDNS(); err != nil {
				log.Warn().Err(err).Msg("Failed to reload Pi-hole DNS after uninstall")
			}
		}
	}

	// Delete from database (cascades to ports and fqdns)
	_, err = o.db.ExecContext(ctx, "DELETE FROM apps WHERE id = ?", app.ID)
	if err != nil {
		return fmt.Errorf("failed to delete app from database: %w", err)
	}

	// Remove compose config directory (always removed on uninstall)
	if app.ComposePath != "" {
		configDir := filepath.Dir(app.ComposePath)
		if err := os.RemoveAll(configDir); err != nil {
			log.Warn().Err(err).Str("path", configDir).Msg("Failed to remove config directory during uninstall")
		}
	}

	// Optionally remove data
	if !keepData && app.DataPath != "" {
		if err := os.RemoveAll(app.DataPath); err != nil {
			log.Warn().Err(err).Str("path", app.DataPath).Msg("Failed to remove data directory during uninstall")
		}
	}

	// Clean up parent app directory if empty
	if app.ComposePath != "" {
		parentDir := filepath.Dir(filepath.Dir(app.ComposePath)) // e.g. /cubeos/apps/appname
		if entries, err := os.ReadDir(parentDir); err == nil && len(entries) == 0 {
			os.Remove(parentDir) // Remove only if empty
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
			deploy_mode, COALESCE(webui_type, 'browser') as webui_type,
			icon_url, version, homepage, created_at, updated_at
		FROM apps WHERE name = ?
	`, name).Scan(
		&app.ID, &app.Name, &app.DisplayName, &app.Description, &app.Type,
		&app.Category, &app.Source, &app.StoreID, &app.ComposePath, &app.DataPath,
		&app.Enabled, &app.TorEnabled, &app.VPNEnabled,
		&app.DeployMode, &app.WebUIType,
		&app.IconURL, &app.Version, &app.Homepage,
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

// ListApps retrieves all apps with optional filtering.
// FIX B115: Close rows before loading app relations to avoid SQLite connection
// contention — same two-pass pattern as ListProfiles.
func (o *Orchestrator) ListApps(ctx context.Context, filter *models.AppFilter) ([]*models.App, error) {
	query := `
		SELECT id, name, display_name, description, type, category, source, store_id,
			compose_path, data_path, enabled, tor_enabled, vpn_enabled,
			deploy_mode, COALESCE(webui_type, 'browser') as webui_type,
			icon_url, version, homepage, created_at, updated_at
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

	// First pass: scan all rows (keep rows open only for scanning)
	var apps []*models.App
	for rows.Next() {
		var app models.App
		err := rows.Scan(
			&app.ID, &app.Name, &app.DisplayName, &app.Description, &app.Type,
			&app.Category, &app.Source, &app.StoreID, &app.ComposePath, &app.DataPath,
			&app.Enabled, &app.TorEnabled, &app.VPNEnabled,
			&app.DeployMode, &app.WebUIType,
			&app.IconURL, &app.Version, &app.Homepage,
			&app.CreatedAt, &app.UpdatedAt,
		)
		if err != nil {
			rows.Close()
			return nil, err
		}
		apps = append(apps, &app)
	}

	// Close rows BEFORE loading relations to free the SQLite connection
	rows.Close()

	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Second pass: load relations and status (connection is now free)
	for _, app := range apps {
		// Get runtime status
		app.Status = o.getAppStatus(ctx, app)

		// Load related data (ports, FQDNs) so frontend can build URLs
		if err := o.loadAppRelations(ctx, app); err != nil {
			log.Warn().Err(err).Str("app", app.Name).Msg("failed to load app relations")
		}
	}

	return apps, nil
}

// =============================================================================
// Reconciliation Operations
// =============================================================================

// coreAppMeta holds display metadata for core CubeOS services.
// Used by SyncAppsFromSwarm to populate the apps table on first boot.
var coreAppMeta = map[string]struct {
	DisplayName string
	Description string
	Type        models.AppType
	Category    string
	DeployMode  models.DeployMode
}{
	"cubeos-api":       {"CubeOS API", "CubeOS REST API server", models.AppTypePlatform, "platform", models.DeployModeStack},
	"cubeos-dashboard": {"CubeOS Dashboard", "Web management dashboard", models.AppTypePlatform, "platform", models.DeployModeStack},
	"registry":         {"Docker Registry", "Local container image registry", models.AppTypeSystem, "infrastructure", models.DeployModeStack},
	"dozzle":           {"Dozzle", "Real-time Docker log viewer", models.AppTypePlatform, "monitoring", models.DeployModeStack},
	"ollama":           {"Ollama", "Local AI model inference server", models.AppTypeAI, "ai", models.DeployModeStack},
	"chromadb":         {"ChromaDB", "AI vector database", models.AppTypeAI, "ai", models.DeployModeStack},
	"pihole":           {"Pi-hole", "DNS sinkhole and DHCP server", models.AppTypeSystem, "infrastructure", models.DeployModeCompose},
	"npm":              {"Nginx Proxy Manager", "Reverse proxy and SSL manager", models.AppTypeSystem, "infrastructure", models.DeployModeCompose},
}

// SyncAppsFromSwarm discovers running Swarm stacks and ensures matching
// records exist in the apps table. Called on API startup so the dashboard
// can display services deployed by first-boot scripts.
func (o *Orchestrator) SyncAppsFromSwarm(ctx context.Context) error {
	if o.swarm == nil {
		log.Warn().Msg("SyncAppsFromSwarm: SwarmManager not available, skipping")
		return nil
	}

	stacks, err := o.swarm.ListStacks()
	if err != nil {
		return fmt.Errorf("failed to list swarm stacks: %w", err)
	}

	synced := 0
	for _, stack := range stacks {
		// Check if app already registered
		var count int
		err := o.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM apps WHERE name = ?", stack.Name).Scan(&count)
		if err != nil {
			log.Warn().Err(err).Str("stack", stack.Name).Msg("SyncAppsFromSwarm: failed to check app existence")
			continue
		}
		if count > 0 {
			continue // Already registered
		}

		// Look up metadata for core apps, use generic defaults for unknown stacks
		meta, known := coreAppMeta[stack.Name]
		if !known {
			meta.DisplayName = stack.Name
			meta.Description = fmt.Sprintf("Docker Swarm stack: %s", stack.Name)
			meta.Type = models.AppTypeUser
			meta.Category = "other"
			meta.DeployMode = models.DeployModeStack
		}

		composePath := filepath.Join("/cubeos/coreapps", stack.Name, "appconfig/docker-compose.yml")
		if _, err := os.Stat(composePath); err != nil {
			composePath = ""
		}

		_, err = o.db.ExecContext(ctx, `
			INSERT INTO apps (name, display_name, description, type, category, source,
				compose_path, data_path, enabled, deploy_mode, webui_type,
				created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, 'cubeos', ?, ?, 1, ?, 'browser',
				CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		`, stack.Name, meta.DisplayName, meta.Description, meta.Type, meta.Category,
			composePath, filepath.Join("/cubeos/apps", stack.Name, "data"),
			meta.DeployMode)

		if err != nil {
			log.Warn().Err(err).Str("stack", stack.Name).Msg("SyncAppsFromSwarm: failed to insert app")
			continue
		}

		synced++
		log.Info().Str("stack", stack.Name).Str("type", string(meta.Type)).Msg("SyncAppsFromSwarm: registered app from Swarm")
	}

	if synced > 0 {
		log.Info().Int("count", synced).Msg("SyncAppsFromSwarm: completed sync")
	}
	return nil
}

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

// SeedSystemPortsAndFQDNs ensures port_allocations and fqdns records exist for
// all core system services. Called after SyncAppsFromSwarm to fill in the records
// that SyncAppsFromSwarm doesn't create. Uses INSERT OR IGNORE for idempotency.
func (o *Orchestrator) SeedSystemPortsAndFQDNs(ctx context.Context) error {
	type systemEntry struct {
		appName   string
		port      int
		subdomain string // empty = skip FQDN
		portDesc  string
	}

	entries := []systemEntry{
		{"pihole", 6001, "pihole", "Admin UI"},
		{"npm", 6000, "npm", "Admin UI"},
		{"cubeos-api", 6010, "api", "REST API"},
		{"cubeos-dashboard", 6011, "cubeos", "Web Dashboard"},
		{"cubeos-hal", 6005, "hal", "Hardware Abstraction"},
		{"registry", 5000, "registry", "Docker Registry"},
		{"dozzle", 6012, "dozzle", "Log Viewer"},
		{"ollama", 6030, "ollama", "AI Inference"},
		{"chromadb", 6031, "chromadb", "Vector DB"},
		{"cubeos-docsindex", 6032, "docs", "Documentation"},
	}

	seededPorts := 0
	seededFQDNs := 0

	for _, e := range entries {
		// Look up app_id — skip if app doesn't exist yet
		var appID int64
		err := o.db.QueryRowContext(ctx,
			"SELECT id FROM apps WHERE name = ?", e.appName).Scan(&appID)
		if err != nil {
			// App not registered (e.g. HAL or docsindex may not have been synced)
			// Create a minimal app record so ports/fqdns have a valid foreign key
			appType := models.AppTypeSystem
			deployMode := models.DeployModeCompose
			switch {
			case e.appName == "cubeos-api" || e.appName == "cubeos-dashboard" || e.appName == "dozzle":
				appType = models.AppTypePlatform
				deployMode = models.DeployModeStack
			case e.appName == "ollama" || e.appName == "chromadb" || e.appName == "cubeos-docsindex":
				appType = models.AppTypeAI
				deployMode = models.DeployModeStack
			case e.appName == "registry":
				deployMode = models.DeployModeStack
			}

			composePath := fmt.Sprintf("/cubeos/coreapps/%s/appconfig/docker-compose.yml", e.appName)
			result, insertErr := o.db.ExecContext(ctx, `
				INSERT OR IGNORE INTO apps (name, display_name, type, category, source,
					compose_path, data_path, enabled, deploy_mode)
				VALUES (?, ?, ?, 'infrastructure', 'cubeos', ?, ?, 1, ?)
			`, e.appName, e.appName, appType, composePath,
				fmt.Sprintf("/cubeos/coreapps/%s/appdata", e.appName), deployMode)
			if insertErr != nil {
				log.Warn().Err(insertErr).Str("app", e.appName).Msg("SeedSystemPortsAndFQDNs: failed to create app record")
				continue
			}
			appID, _ = result.LastInsertId()
			if appID == 0 {
				// INSERT OR IGNORE hit a conflict — re-query
				_ = o.db.QueryRowContext(ctx,
					"SELECT id FROM apps WHERE name = ?", e.appName).Scan(&appID)
			}
			if appID == 0 {
				continue
			}
		}

		// Seed port allocation
		result, err := o.db.ExecContext(ctx, `
			INSERT OR IGNORE INTO port_allocations (app_id, port, protocol, description, is_primary)
			VALUES (?, ?, 'tcp', ?, TRUE)
		`, appID, e.port, e.portDesc)
		if err == nil {
			if rows, _ := result.RowsAffected(); rows > 0 {
				seededPorts++
			}
		}

		// Seed FQDN
		if e.subdomain != "" {
			fqdn := fmt.Sprintf("%s.%s", e.subdomain, o.cfg.Domain)
			result, err = o.db.ExecContext(ctx, `
				INSERT OR IGNORE INTO fqdns (app_id, fqdn, subdomain, backend_port)
				VALUES (?, ?, ?, ?)
			`, appID, fqdn, e.subdomain, e.port)
			if err == nil {
				if rows, _ := result.RowsAffected(); rows > 0 {
					seededFQDNs++
				}
			}
		}
	}

	if seededPorts > 0 || seededFQDNs > 0 {
		log.Info().Int("ports", seededPorts).Int("fqdns", seededFQDNs).
			Msg("SeedSystemPortsAndFQDNs: seeded system records")
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
		if o.swarm == nil {
			return status
		}
		// Get aggregate status across all services in the stack.
		// Uses stack namespace label — works for CasaOS apps where the
		// compose service name differs from the app/stack name.
		stackStatus, err := o.swarm.GetStackStatus(app.Name)
		if err == nil && stackStatus != nil {
			status.Running = stackStatus.Running
			status.Replicas = stackStatus.Replicas
			status.Health = stackStatus.Health
			if !status.Running {
				status.Health = "stopped"
			}
		}
	} else {
		if o.docker == nil {
			return status
		}
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

// torTransparentPort is the Tor transparent proxy port exposed by the Tor coreapp.
const torTransparentPort = "9040"

// torDNSPort is the Tor DNS resolver port.
const torDNSPort = "5353"

// SetAppTor enables or disables Tor routing for an app.
// When enabled, the app's outbound TCP traffic is redirected through the Tor
// transparent proxy via iptables DNAT rules on the host (applied via HAL).
// The preference is always persisted to the database; actual iptables rules
// are only applied if the Tor service is reachable and the app container is
// running.
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

	// Attempt to apply iptables rules via HAL
	if o.hal == nil {
		log.Warn().Str("app", name).Bool("enabled", enabled).
			Msg("tor preference saved, HAL client unavailable — rules not applied")
		return nil
	}

	if err := o.applyTorRouting(ctx, name, enabled); err != nil {
		// Log but don't fail — the preference is saved, rules can be reconciled later
		log.Warn().Err(err).Str("app", name).Bool("enabled", enabled).
			Msg("tor preference saved, failed to apply iptables rules (will reconcile)")
	}

	return nil
}

// applyTorRouting adds or removes iptables rules to redirect an app's traffic
// through the Tor transparent proxy.
func (o *Orchestrator) applyTorRouting(ctx context.Context, appName string, enabled bool) error {
	// Resolve the app's container IP on docker_gwbridge
	containerIP, err := o.resolveContainerIP(ctx, appName)
	if err != nil {
		return fmt.Errorf("cannot resolve container IP for %s: %w", appName, err)
	}

	if enabled {
		// Verify Tor is running before adding rules
		torStatus, err := o.hal.GetTorStatus(ctx)
		if err != nil || torStatus == nil || !torStatus.Running {
			return fmt.Errorf("tor service is not running — start Tor before enabling per-app routing")
		}

		// Redirect TCP traffic from this container through Tor transparent proxy
		// nat/PREROUTING: DNAT TCP from container → Tor TransPort
		err = o.hal.AddFirewallRule(ctx, "nat", "PREROUTING", []string{
			"-s", containerIP, "-p", "tcp",
			"!", "-d", "10.42.24.0/24",
			"-j", "REDIRECT", "--to-ports", torTransparentPort,
			"-m", "comment", "--comment", "cubeos-tor:" + appName,
		})
		if err != nil {
			return fmt.Errorf("failed to add Tor TCP redirect rule: %w", err)
		}

		// Redirect DNS from this container through Tor DNS
		err = o.hal.AddFirewallRule(ctx, "nat", "PREROUTING", []string{
			"-s", containerIP, "-p", "udp", "--dport", "53",
			"-j", "REDIRECT", "--to-ports", torDNSPort,
			"-m", "comment", "--comment", "cubeos-tor-dns:" + appName,
		})
		if err != nil {
			return fmt.Errorf("failed to add Tor DNS redirect rule: %w", err)
		}

		log.Info().Str("app", appName).Str("ip", containerIP).
			Msg("tor routing enabled via iptables")
	} else {
		// Remove Tor rules for this app (best-effort, ignore errors for missing rules)
		_ = o.hal.DeleteFirewallRule(ctx, "nat", "PREROUTING", []string{
			"-s", containerIP, "-p", "tcp",
			"!", "-d", "10.42.24.0/24",
			"-j", "REDIRECT", "--to-ports", torTransparentPort,
			"-m", "comment", "--comment", "cubeos-tor:" + appName,
		})
		_ = o.hal.DeleteFirewallRule(ctx, "nat", "PREROUTING", []string{
			"-s", containerIP, "-p", "udp", "--dport", "53",
			"-j", "REDIRECT", "--to-ports", torDNSPort,
			"-m", "comment", "--comment", "cubeos-tor-dns:" + appName,
		})

		log.Info().Str("app", appName).Str("ip", containerIP).
			Msg("tor routing disabled, iptables rules removed")
	}

	return nil
}

// SetAppVPN enables or disables VPN routing for an app.
// When enabled, the app's outbound traffic is policy-routed through the active
// VPN tunnel interface via iptables mark + ip rule on the host (applied via HAL).
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

	// Attempt to apply iptables rules via HAL
	if o.hal == nil {
		log.Warn().Str("app", name).Bool("enabled", enabled).
			Msg("vpn preference saved, HAL client unavailable — rules not applied")
		return nil
	}

	if err := o.applyVPNRouting(ctx, name, enabled); err != nil {
		log.Warn().Err(err).Str("app", name).Bool("enabled", enabled).
			Msg("vpn preference saved, failed to apply iptables rules (will reconcile)")
	}

	return nil
}

// vpnFwMark is the fwmark value used for VPN policy routing.
// Traffic from VPN-enabled containers is marked with this value,
// and an ip rule routes marked traffic through the VPN table.
const vpnFwMark = "0x1"

// applyVPNRouting adds or removes iptables mark rules for VPN policy routing.
func (o *Orchestrator) applyVPNRouting(ctx context.Context, appName string, enabled bool) error {
	containerIP, err := o.resolveContainerIP(ctx, appName)
	if err != nil {
		return fmt.Errorf("cannot resolve container IP for %s: %w", appName, err)
	}

	if enabled {
		// Verify VPN is active before adding rules
		vpnStatus, err := o.hal.GetVPNStatus(ctx)
		if err != nil {
			return fmt.Errorf("failed to check VPN status: %w", err)
		}
		if vpnStatus == nil || (!vpnStatus.WireGuard.Active && !vpnStatus.OpenVPN.Active) {
			return fmt.Errorf("no active VPN tunnel — connect a VPN before enabling per-app routing")
		}

		// Mark traffic from this container for VPN routing
		// mangle/PREROUTING: set fwmark on packets from container
		err = o.hal.AddFirewallRule(ctx, "mangle", "PREROUTING", []string{
			"-s", containerIP,
			"!", "-d", "10.42.24.0/24",
			"-j", "MARK", "--set-mark", vpnFwMark,
			"-m", "comment", "--comment", "cubeos-vpn:" + appName,
		})
		if err != nil {
			return fmt.Errorf("failed to add VPN mark rule: %w", err)
		}

		log.Info().Str("app", appName).Str("ip", containerIP).
			Msg("vpn routing enabled via fwmark")
	} else {
		// Remove VPN mark rule (best-effort)
		_ = o.hal.DeleteFirewallRule(ctx, "mangle", "PREROUTING", []string{
			"-s", containerIP,
			"!", "-d", "10.42.24.0/24",
			"-j", "MARK", "--set-mark", vpnFwMark,
			"-m", "comment", "--comment", "cubeos-vpn:" + appName,
		})

		log.Info().Str("app", appName).Str("ip", containerIP).
			Msg("vpn routing disabled, iptables rules removed")
	}

	return nil
}

// resolveContainerIP finds the container's IP on the docker_gwbridge network
// by inspecting Docker containers matching the app's Swarm service name.
func (o *Orchestrator) resolveContainerIP(ctx context.Context, appName string) (string, error) {
	if o.docker == nil {
		return "", fmt.Errorf("docker manager unavailable")
	}

	// Swarm service naming: stack_service → try the swarm task container name
	// Convention: services are named as "{appName}_{appName}" or just "{appName}"
	// Try the most common patterns
	candidates := []string{
		appName + "_" + appName, // stack_service pattern
		appName,                 // direct name
	}

	for _, name := range candidates {
		ip, err := o.docker.GetContainerIP(ctx, name)
		if err == nil && ip != "" {
			return ip, nil
		}
	}

	// Fallback: scan all containers for a match
	containers, err := o.docker.ListContainers(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to list containers: %w", err)
	}

	for _, c := range containers {
		if c.State != "running" {
			continue
		}
		if strings.HasPrefix(c.Name, appName+"_") || strings.HasPrefix(c.Name, appName+".") {
			// Found a matching container — inspect it for IP
			ip, err := o.docker.GetContainerIP(ctx, c.ID)
			if err == nil && ip != "" {
				return ip, nil
			}
		}
	}

	return "", fmt.Errorf("no running container found for app %s", appName)
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

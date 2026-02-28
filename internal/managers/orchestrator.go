// Package managers provides the Orchestrator for unified app management.
package managers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"cubeos-api/internal/circuitbreaker"
	"cubeos-api/internal/config"
	"cubeos-api/internal/flowengine"
	feworkflows "cubeos-api/internal/flowengine/workflows"
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
	engine         *flowengine.WorkflowEngine
	feStore        *flowengine.WorkflowStore
}

// OrchestratorConfig holds configuration for the Orchestrator
type OrchestratorConfig struct {
	DB            *sql.DB
	Config        *config.Config
	CoreappsPath  string
	AppsPath      string
	NPMConfigDir  string
	HALClient     *hal.Client
	RegistryURL   string                         // Local Docker registry URL (e.g. http://10.42.24.1:5000)
	DockerCB      *circuitbreaker.CircuitBreaker // Shared Docker circuit breaker (used by internal DockerManager + fallback SwarmManager)
	SwarmManager  *SwarmManager                  // Optional: shared instance; if nil, one is created internally
	NPMManager    *NPMManager                    // Optional: shared instance; if nil, one is created internally
	PiholeManager *PiholeManager                 // Optional: shared instance; if nil, one is created internally
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
		o.swarm, err = NewSwarmManager(cfg.DockerCB)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to create swarm manager: %w", err)
		}
	}

	// Initialize DockerManager
	o.docker, err = NewDockerManager(cfg.Config, cfg.DockerCB)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create docker manager: %w", err)
	}

	// Initialize NPMManager (use shared instance if provided)
	if cfg.NPMManager != nil {
		o.npm = cfg.NPMManager
	} else {
		npmConfigDir := cfg.NPMConfigDir
		if npmConfigDir == "" {
			npmConfigDir = "/cubeos/coreapps/npm/appdata"
		}
		o.npm = NewNPMManager(cfg.Config, npmConfigDir)
		if err := o.npm.Init(); err != nil {
			log.Warn().Err(err).Msg("Orchestrator: NPM init failed, proxy operations will fail")
		}
	}

	// Initialize PiholeManager (use shared instance if provided)
	if cfg.PiholeManager != nil {
		o.pihole = cfg.PiholeManager
	} else {
		o.pihole = NewPiholeManager(cfg.Config)
	}

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

// SetFlowEngine wires the WorkflowEngine and WorkflowStore into the Orchestrator.
// Call this after engine.Start() so the engine is ready before workflows are submitted.
func (o *Orchestrator) SetFlowEngine(e *flowengine.WorkflowEngine, s *flowengine.WorkflowStore) {
	o.engine = e
	o.feStore = s
}

// AppExists reports whether an app with the given name already exists in the database.
// Implements activities.AppConflictChecker via adapters in main.
func (o *Orchestrator) AppExists(ctx context.Context, name string) (bool, error) {
	var count int
	err := o.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM apps WHERE name = ?", name).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// =============================================================================
// App Lifecycle Operations
// =============================================================================

// InstallApp submits an app_install workflow and returns immediately.
// The workflow executes asynchronously; callers should return 202 Accepted
// with the workflow ID for the client to poll progress.
// Returns (nil, nil) to signal an async in-progress install.
func (o *Orchestrator) InstallApp(ctx context.Context, req models.InstallAppRequest) (*models.App, error) {
	name := strings.ToLower(strings.TrimSpace(req.Name))
	if name == "" {
		return nil, fmt.Errorf("app name is required")
	}
	if !isValidAppName(name) {
		return nil, fmt.Errorf("invalid app name: must be lowercase alphanumeric with hyphens")
	}

	if o.engine == nil {
		return nil, fmt.Errorf("workflow engine not available")
	}

	basePath := "/cubeos/apps"
	if req.Type == models.AppTypeSystem || req.Type == models.AppTypePlatform {
		basePath = "/cubeos/coreapps"
	}
	composePath := filepath.Join(basePath, name, "appconfig", "docker-compose.yml")
	dataPath := filepath.Join(basePath, name, "appdata")

	source := string(req.Source)
	if source == "" {
		source = "custom"
	}

	input, err := json.Marshal(map[string]interface{}{
		"name":         name,
		"app_name":     name,
		"stack_name":   name,
		"source":       source,
		"image":        req.Image,
		"tag":          req.Tag,
		"compose_path": composePath,
		"base_path":    basePath,
		"data_path":    dataPath,
		"base_domain":  o.cfg.Domain,
		"enabled":      true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build workflow input: %w", err)
	}

	if _, err := o.engine.Submit(ctx, flowengine.SubmitParams{
		WorkflowType: feworkflows.AppInstallType,
		ExternalID:   name,
		Input:        json.RawMessage(input),
	}); err != nil {
		return nil, fmt.Errorf("failed to submit install workflow: %w", err)
	}

	// Return nil to signal async in-progress. Handler must return 202 Accepted.
	return nil, nil
}

// InstallFromRegistryWithProgress submits an app_install workflow for a registry image
// and polls for completion while emitting SSE progress events via job.
// Returns the installed app on success, or an error if the workflow fails.
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

	if o.engine == nil || o.feStore == nil {
		return nil, fmt.Errorf("workflow engine not available")
	}

	job.Emit("setup", 10, "Preparing installation")

	// Pre-allocate a port so the compose YAML can reference it before the workflow starts.
	allocatedPort, err := o.ports.AllocateUserPort()
	if err != nil {
		return nil, fmt.Errorf("failed to allocate port: %w", err)
	}

	job.Emit("port", 20, fmt.Sprintf("Allocated port %d", allocatedPort))

	appBase := filepath.Join("/cubeos/apps", name)
	appConfig := filepath.Join(appBase, "appconfig")
	appData := filepath.Join(appBase, "appdata")
	composePath := filepath.Join(appConfig, "docker-compose.yml")
	fullImage := fmt.Sprintf("localhost:5000/%s:%s", req.Image, req.Tag)

	// Generate compose YAML with the allocated port.
	// The app_install workflow's allocate_port step will see port>0 in the input and
	// use it directly without re-allocating.
	composeYAML := fmt.Sprintf(`services:
  %s:
    image: %s
    ports:
      - target: 8080
        published: %d
        mode: host
    deploy:
      replicas: 1
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
    volumes:
      - %s:/data
`, name, fullImage, allocatedPort, appData)

	subdomain := name
	if req.Subdomain != "" {
		subdomain = strings.ToLower(strings.TrimSpace(req.Subdomain))
	}

	input, err := json.Marshal(map[string]interface{}{
		"name":         name,
		"app_name":     name,
		"stack_name":   name,
		"source":       string(models.AppSourceRegistry),
		"image":        req.Image,
		"tag":          req.Tag,
		"compose_yaml": composeYAML,
		"base_path":    appBase,
		"compose_path": composePath,
		"data_path":    appData,
		"base_domain":  o.cfg.Domain,
		"subdomain":    subdomain,
		"port":         allocatedPort, // hint for db.allocate_port (uses this instead of auto-alloc)
		"enabled":      true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build workflow input: %w", err)
	}

	wf, err := o.engine.Submit(ctx, flowengine.SubmitParams{
		WorkflowType: feworkflows.AppInstallType,
		ExternalID:   name,
		Input:        json.RawMessage(input),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to submit install workflow: %w", err)
	}

	adapter := flowengine.NewProgressAdapter(job)
	if err := adapter.PollAndEmit(ctx, o.feStore, wf.ID); err != nil {
		return nil, err
	}

	return o.GetApp(ctx, name)
}

// UninstallApp submits an app_remove workflow and waits for completion.
// Protected system apps cannot be uninstalled.
func (o *Orchestrator) UninstallApp(ctx context.Context, name string, keepData bool) error {
	app, err := o.GetApp(ctx, name)
	if err != nil {
		return fmt.Errorf("app not found: %w", err)
	}

	if app.IsProtected() {
		return fmt.Errorf("cannot uninstall protected system app: %s", name)
	}

	if o.engine == nil || o.feStore == nil {
		return fmt.Errorf("workflow engine not available")
	}

	// Resolve primary FQDN from the already-loaded app relations.
	fqdn := app.GetPrimaryFQDN()

	input, err := json.Marshal(feworkflows.AppRemoveInput{
		AppID:       app.ID,
		AppName:     name,
		FQDN:        fqdn,
		ComposePath: app.ComposePath,
		DataPath:    app.DataPath,
		KeepData:    keepData,
		UsesSwarm:   app.UsesSwarm(),
	})
	if err != nil {
		return fmt.Errorf("failed to build workflow input: %w", err)
	}

	wf, err := o.engine.Submit(ctx, flowengine.SubmitParams{
		WorkflowType: feworkflows.AppRemoveWorkflowType,
		ExternalID:   name,
		Input:        json.RawMessage(input),
	})
	if err != nil {
		return fmt.Errorf("failed to submit remove workflow: %w", err)
	}

	return flowengine.WaitForCompletion(ctx, o.feStore, wf.ID)
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
	"cubeos-docsindex": {"CubeOS Docs", "Offline documentation server", models.AppTypePlatform, "platform", models.DeployModeStack},
	"ollama":           {"Ollama", "Local LLM inference engine", models.AppTypeAI, "ai", models.DeployModeStack},
	"chromadb":         {"ChromaDB", "Vector database for AI embeddings", models.AppTypeAI, "ai", models.DeployModeStack},
	"pihole":           {"Pi-hole", "DNS sinkhole and DHCP server", models.AppTypeSystem, "infrastructure", models.DeployModeCompose},
	"npm":              {"Nginx Proxy Manager", "Reverse proxy and SSL manager", models.AppTypeSystem, "infrastructure", models.DeployModeCompose},
	"cubeos-hal":       {"CubeOS HAL", "Hardware Abstraction Layer", models.AppTypeSystem, "infrastructure", models.DeployModeCompose},
	"kiwix":            {"Kiwix Offline Library", "Offline encyclopedia and content library", models.AppTypePlatform, "library", models.DeployModeStack},
	"filebrowser":      {"File Browser", "Web-based file manager", models.AppTypePlatform, "storage", models.DeployModeStack},
	"cubeos-terminal":  {"Web Terminal", "Browser-based terminal access", models.AppTypePlatform, "system", models.DeployModeCompose},
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
		{"npm", "Nginx Proxy Manager", models.AppTypeSystem, 81, models.DeployModeCompose},
		{"cubeos-hal", "CubeOS HAL", models.AppTypeSystem, 6005, models.DeployModeCompose},
		{"registry", "Docker Registry", models.AppTypeSystem, 5000, models.DeployModeStack},
		{"cubeos-api", "CubeOS API", models.AppTypePlatform, 6010, models.DeployModeStack},
		{"cubeos-dashboard", "CubeOS Dashboard", models.AppTypePlatform, 6011, models.DeployModeStack},
		{"dozzle", "Dozzle", models.AppTypePlatform, 6012, models.DeployModeStack},
		{"cubeos-docsindex", "CubeOS Docs", models.AppTypePlatform, 6032, models.DeployModeStack},
		{"ollama", "Ollama", models.AppTypeAI, 6030, models.DeployModeStack},
		{"chromadb", "ChromaDB", models.AppTypeAI, 6031, models.DeployModeStack},
		{"kiwix", "Kiwix Offline Library", models.AppTypePlatform, 6043, models.DeployModeStack},
		{"filebrowser", "File Browser", models.AppTypePlatform, 6013, models.DeployModeStack},
		{"cubeos-terminal", "Web Terminal", models.AppTypePlatform, 6042, models.DeployModeCompose},
	}

	// First pass: update display names for any already-registered apps that
	// were synced by SyncAppsFromSwarm before coreAppMeta was complete.
	for _, sa := range systemApps {
		_, err := o.db.ExecContext(ctx, `
			UPDATE apps SET display_name = ? WHERE name = ? AND display_name = ?
		`, sa.displayName, sa.name, sa.name)
		if err != nil {
			log.Warn().Err(err).Str("app", sa.name).Msg("SeedSystemApps: failed to update display name")
		}
	}

	// Second pass: insert any missing system apps
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
		{"npm", 81, "npm", "Admin UI"},
		{"cubeos-api", 6010, "api", "REST API"},
		{"cubeos-dashboard", 6011, "cubeos", "Web Dashboard"},
		{"cubeos-hal", 6005, "hal", "Hardware Abstraction"},
		{"registry", 5000, "registry", "Docker Registry"},
		{"dozzle", 6012, "dozzle", "Log Viewer"},
		{"ollama", 6030, "ollama", "AI Inference"},
		{"chromadb", 6031, "chromadb", "Vector DB"},
		{"cubeos-docsindex", 6032, "docs", "Documentation"},
		{"kiwix", 6043, "kiwix", "Offline Library"},
		{"filebrowser", 6013, "filebrowser", "File Manager"},
		{"cubeos-terminal", 6042, "terminal", "Web Terminal"},
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
			case e.appName == "cubeos-api" || e.appName == "cubeos-dashboard" || e.appName == "dozzle" ||
				e.appName == "cubeos-docsindex" || e.appName == "kiwix" || e.appName == "filebrowser":
				appType = models.AppTypePlatform
				deployMode = models.DeployModeStack
			case e.appName == "cubeos-terminal":
				appType = models.AppTypePlatform
				deployMode = models.DeployModeCompose
			case e.appName == "ollama" || e.appName == "chromadb":
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

// PruneOrphanApps removes database records for non-protected apps whose
// underlying Docker service or container no longer exists. Called after
// SyncAppsFromSwarm + SeedSystemApps to clean up ghost entries left behind
// by failed installs or services removed outside the API.
func (o *Orchestrator) PruneOrphanApps(ctx context.Context) error {
	rows, err := o.db.QueryContext(ctx, `
		SELECT id, name, deploy_mode, compose_path, type FROM apps
	`)
	if err != nil {
		return fmt.Errorf("PruneOrphanApps: failed to query apps: %w", err)
	}

	type candidate struct {
		id          int64
		name        string
		deployMode  models.DeployMode
		composePath string
		appType     models.AppType
	}

	var candidates []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.id, &c.name, &c.deployMode, &c.composePath, &c.appType); err != nil {
			rows.Close()
			return fmt.Errorf("PruneOrphanApps: failed to scan app: %w", err)
		}
		candidates = append(candidates, c)
	}
	rows.Close()

	pruned := 0
	for _, c := range candidates {
		// Never prune protected apps (system + platform types)
		if c.appType == models.AppTypeSystem || c.appType == models.AppTypePlatform {
			continue
		}

		orphan := false

		if c.deployMode == models.DeployModeStack {
			// Check if Swarm stack still exists
			if o.swarm != nil {
				exists, err := o.swarm.StackExists(c.name)
				if err != nil {
					log.Warn().Err(err).Str("app", c.name).Msg("PruneOrphanApps: failed to check stack, skipping")
					continue
				}
				if exists {
					continue // Stack exists — not an orphan
				}
			} else {
				continue // Can't verify without Swarm — don't prune
			}

			// Stack gone — also check if compose file exists on disk
			if c.composePath != "" {
				if _, err := os.Stat(c.composePath); err == nil {
					continue // Compose file still on disk — could be redeployed
				}
			}
			orphan = true

		} else if c.deployMode == models.DeployModeCompose {
			// Check if Docker container exists
			if o.docker != nil {
				containerName := c.name
				if !strings.HasPrefix(containerName, "cubeos-") {
					containerName = "cubeos-" + containerName
				}
				checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				status, err := o.docker.GetContainerStatus(checkCtx, containerName)
				cancel()
				if err != nil {
					log.Warn().Err(err).Str("app", c.name).Msg("PruneOrphanApps: failed to check container, skipping")
					continue
				}
				if status != "not_found" {
					continue // Container exists — not an orphan
				}
			} else {
				continue // Can't verify without Docker — don't prune
			}

			// Container gone — also check compose file on disk
			if c.composePath != "" {
				if _, err := os.Stat(c.composePath); err == nil {
					continue // Compose file still on disk — could be restarted
				}
			}
			orphan = true
		}

		if !orphan {
			continue
		}

		// Delete the orphan record (cascading deletes handle port_allocations + fqdns)
		_, err := o.db.ExecContext(ctx, "DELETE FROM apps WHERE id = ?", c.id)
		if err != nil {
			log.Warn().Err(err).Str("app", c.name).Int64("id", c.id).Msg("PruneOrphanApps: failed to delete orphan")
			continue
		}

		pruned++
		log.Info().Str("app", c.name).Int64("id", c.id).Str("deploy_mode", string(c.deployMode)).
			Msg("PruneOrphanApps: removed orphan app record")
	}

	if pruned > 0 {
		log.Info().Int("count", pruned).Msg("PruneOrphanApps: cleanup complete")
	} else {
		log.Debug().Msg("PruneOrphanApps: no orphans found")
	}

	return nil
}

// =============================================================================
// Helper Functions
// =============================================================================

func (o *Orchestrator) getAppStatus(ctx context.Context, app *models.App) *models.AppStatus {
	status := &models.AppStatus{
		Running: false,
		Health:  "unknown",
	}

	if app.UsesSwarm() {
		var swarmFound bool
		if o.swarm != nil {
			// Get aggregate status across all services in the stack.
			// Uses stack namespace label — works for CasaOS apps where the
			// compose service name differs from the app/stack name.
			stackStatus, err := o.swarm.GetStackStatus(app.Name)
			if err == nil && stackStatus != nil && stackStatus.Replicas != "" {
				swarmFound = true
				status.Running = stackStatus.Running
				status.Replicas = stackStatus.Replicas
				status.Health = stackStatus.Health
				if !status.Running {
					status.Health = "stopped"
				}
			}
		}

		// Tier 2 (container) installs deploy ALL services via docker-compose,
		// but the DB registers platform services with deploy_mode=stack.
		// When the Swarm lookup finds nothing, fall back to plain Docker
		// container status check.
		if !swarmFound && o.docker != nil {
			containerName := app.Name
			if !strings.HasPrefix(containerName, "cubeos-") {
				containerName = "cubeos-" + containerName
			}
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
	} else {
		if o.docker == nil {
			return status
		}
		// Get status from Docker with timeout context
		// Container naming convention: compose files use "cubeos-{name}" as
		// container_name. Apps whose name already starts with "cubeos-" (like
		// cubeos-hal) use the name directly to avoid double-prefixing.
		containerName := app.Name
		if !strings.HasPrefix(containerName, "cubeos-") {
			containerName = "cubeos-" + containerName
		}
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
		// Look up actual service names from the stack — the compose service
		// name often differs from the stack/app name (e.g. CasaOS apps like
		// "big-bear-it-tools" may have a compose service named "it-tools").
		serviceName := ""
		if o.swarm != nil {
			services, err := o.swarm.GetStackServices(name)
			if err == nil && len(services) > 0 {
				serviceName = services[0].Name
			}
		}
		if serviceName == "" {
			// Fallback: assume stack_stack pattern (legacy behaviour)
			serviceName = name + "_" + name
		}
		return o.swarm.GetServiceLogs(serviceName, lines)
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

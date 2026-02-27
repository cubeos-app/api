package managers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"cubeos-api/internal/flowengine"
	feworkflows "cubeos-api/internal/flowengine/workflows"
	"cubeos-api/internal/models"

	"github.com/rs/zerolog/log"
)

// InstallAppWithProgress runs the app store install pipeline as a FlowEngine workflow.
// Emits SSE progress events via PollAndEmit while the workflow executes asynchronously.
// Returns a minimal InstalledApp with the WebUI URL on success so the caller can emit
// the app URL in EmitDone.
func (m *AppStoreManager) InstallAppWithProgress(req *models.AppInstallRequest, job *Job) (*models.InstalledApp, error) {
	job.SetStatus(JobRunning)
	job.Emit("validate", 5, "Starting installation...")

	if m.engine == nil || m.feStore == nil {
		return nil, fmt.Errorf("workflow engine not available")
	}

	basePath := filepath.Join(m.appsPath, req.AppName)
	composePath := filepath.Join(basePath, "appconfig", "docker-compose.yml")
	dataPath := filepath.Join(basePath, "appdata")

	// Look up catalog entry for cache metadata (icon, category, tagline).
	// These flow through the fat envelope to the auto-cache steps.
	title := req.AppName
	icon := ""
	category := ""
	tagline := ""
	if storeApp := m.GetApp(req.StoreID, req.AppName); storeApp != nil {
		if t, ok := storeApp.Title["en_us"]; ok && t != "" {
			title = t
		}
		icon = storeApp.Icon
		category = storeApp.Category
		if t, ok := storeApp.Tagline["en_us"]; ok {
			tagline = t
		}
	}

	input, err := json.Marshal(map[string]interface{}{
		"store_id":      req.StoreID,
		"app_name":      req.AppName,
		"name":          req.AppName,
		"stack_name":    req.AppName,
		"base_path":     basePath,
		"compose_path":  composePath,
		"data_path":     dataPath,
		"source":        "casaos",
		"enabled":       true,
		"base_domain":   m.baseDomain,
		"title":         title,
		"icon":          icon,
		"category":      category,
		"tagline":       tagline,
		"registry_host": os.Getenv("REGISTRY_HOST"),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build workflow input: %w", err)
	}

	wf, err := m.engine.Submit(context.Background(), flowengine.SubmitParams{
		WorkflowType: feworkflows.AppStoreInstallType,
		ExternalID:   req.AppName,
		Input:        json.RawMessage(input),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to submit install workflow: %w", err)
	}

	adapter := flowengine.NewProgressAdapter(job)
	if err := adapter.PollAndEmit(context.Background(), m.feStore, wf.ID); err != nil {
		return nil, err
	}

	// Build WebUI URL: prefer FQDN, fall back to IP:port for standard profile.
	var webUI string
	m.db.db.QueryRow("SELECT COALESCE(homepage, '') FROM apps WHERE name = ?", req.AppName).Scan(&webUI) //nolint:errcheck
	if webUI == "" {
		// Build URL from allocated port + gateway IP (works on all profiles)
		var port int
		m.db.db.QueryRow(`
			SELECT pa.port FROM port_allocations pa
			JOIN apps a ON pa.app_id = a.id
			WHERE a.name = ? AND pa.is_primary = 1
		`, req.AppName).Scan(&port) //nolint:errcheck
		if port > 0 {
			gatewayIP := os.Getenv("GATEWAY_IP")
			if gatewayIP == "" {
				gatewayIP = "10.42.24.1"
			}
			webUI = fmt.Sprintf("http://%s:%d", gatewayIP, port)
		}
	}

	// Update in-memory catalog state so subsequent ListInstalledApps reflects the new app.
	storeApp := m.GetApp(req.StoreID, req.AppName) // takes RLock — must be before Write lock
	installed := &models.InstalledApp{
		ID:    req.AppName,
		Name:  req.AppName,
		WebUI: webUI,
	}
	m.mu.Lock()
	m.installed[req.AppName] = installed
	if storeApp != nil {
		if catalog, ok := m.catalog[storeApp.ID]; ok {
			catalog.Installed = true
		}
	}
	m.mu.Unlock()

	log.Info().Str("app", req.AppName).Msg("app installed via FlowEngine workflow")
	return installed, nil
}

// RemoveAppWithProgress runs the app store remove pipeline as a FlowEngine workflow.
// Emits SSE progress events via PollAndEmit while the workflow executes asynchronously.
func (m *AppStoreManager) RemoveAppWithProgress(appID string, deleteData bool, job *Job) error {
	job.SetStatus(JobRunning)
	job.Emit("validate", 5, "Validating app...")

	if m.engine == nil || m.feStore == nil {
		return fmt.Errorf("workflow engine not available")
	}

	app := m.GetInstalledApp(appID)
	if app == nil {
		return fmt.Errorf("app not found: %s", appID)
	}

	// Fetch DB id and primary FQDN from the unified apps table.
	var dbAppID int64
	m.db.db.QueryRow("SELECT id FROM apps WHERE name = ?", appID).Scan(&dbAppID) //nolint:errcheck

	var fqdn string
	m.db.db.QueryRow( //nolint:errcheck
		`SELECT f.fqdn FROM fqdns f JOIN apps a ON a.id = f.app_id WHERE a.name = ? LIMIT 1`,
		appID,
	).Scan(&fqdn)

	input, err := json.Marshal(feworkflows.AppRemoveInput{
		AppID:       dbAppID,
		AppName:     appID,
		FQDN:        fqdn,
		ComposePath: app.ComposeFile,
		DataPath:    app.DataPath,
		KeepData:    !deleteData,
		UsesSwarm:   true, // store apps are always deployed as Swarm stacks
	})
	if err != nil {
		return fmt.Errorf("failed to build workflow input: %w", err)
	}

	wf, err := m.engine.Submit(context.Background(), flowengine.SubmitParams{
		WorkflowType: feworkflows.AppStoreRemoveType,
		ExternalID:   appID,
		Input:        json.RawMessage(input),
	})
	if err != nil {
		return fmt.Errorf("failed to submit remove workflow: %w", err)
	}

	adapter := flowengine.NewProgressAdapter(job)
	if err := adapter.PollAndEmit(context.Background(), m.feStore, wf.ID); err != nil {
		return err
	}

	// Update in-memory state: remove from installed map and mark catalog entry as uninstalled.
	storeAppID := app.StoreAppID
	m.mu.Lock()
	delete(m.installed, appID)
	if storeAppID != "" {
		if storeApp, ok := m.catalog[storeAppID]; ok {
			storeApp.Installed = false
		}
	}
	m.mu.Unlock()

	log.Info().Str("app", appID).Msg("app removed via FlowEngine workflow")
	return nil
}

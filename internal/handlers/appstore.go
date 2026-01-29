package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"

	"cubeos-api/internal/managers"
	"cubeos-api/internal/models"

	"github.com/go-chi/chi/v5"
)

// AppStoreHandler handles app store API requests
type AppStoreHandler struct {
	manager *managers.AppStoreManager
}

// NewAppStoreHandler creates a new app store handler
func NewAppStoreHandler(manager *managers.AppStoreManager) *AppStoreHandler {
	return &AppStoreHandler{manager: manager}
}

// Routes returns the router for app store endpoints
func (h *AppStoreHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Store management
	r.Get("/stores", h.GetStores)
	r.Post("/stores", h.RegisterStore)
	r.Get("/stores/{storeID}", h.GetStore)
	r.Delete("/stores/{storeID}", h.RemoveStore)
	r.Post("/stores/{storeID}/sync", h.SyncStore)
	r.Post("/stores/sync", h.SyncAllStores)

	// App catalog
	r.Get("/apps", h.GetApps)
	r.Get("/categories", h.GetCategories)
	r.Get("/stores/{storeID}/apps/{appName}", h.GetApp)
	r.Get("/stores/{storeID}/apps/{appName}/manifest", h.GetAppManifest)
	r.Get("/stores/{storeID}/apps/{appName}/icon", h.GetAppIcon)
	r.Get("/stores/{storeID}/apps/{appName}/screenshot/{index}", h.GetAppScreenshot)

	// Installed apps
	r.Get("/installed", h.GetInstalledApps)
	r.Post("/installed", h.InstallApp)
	r.Get("/installed/{appID}", h.GetInstalledApp)
	r.Delete("/installed/{appID}", h.RemoveApp)
	r.Post("/installed/{appID}/start", h.StartApp)
	r.Post("/installed/{appID}/stop", h.StopApp)
	r.Post("/installed/{appID}/restart", h.RestartApp)
	r.Post("/installed/{appID}/action", h.AppAction)

	// Config editor for user apps (/cubeos/apps/)
	r.Get("/installed/{appID}/config", h.GetAppConfig)
	r.Put("/installed/{appID}/config", h.UpdateAppConfig)
	r.Post("/installed/{appID}/config/apply", h.ApplyAppConfig)
	r.Get("/installed/{appID}/config/backups", h.GetConfigBackups)
	r.Post("/installed/{appID}/config/restore/{backup}", h.RestoreConfigBackup)

	// Core apps (/cubeos/coreapps/) - protected with extra warnings
	r.Get("/coreapps", h.ListCoreApps)
	r.Get("/coreapps/{appID}/config", h.GetCoreAppConfig)
	r.Put("/coreapps/{appID}/config", h.UpdateCoreAppConfig)
	r.Post("/coreapps/{appID}/config/apply", h.ApplyCoreAppConfig)
	r.Get("/coreapps/{appID}/config/backups", h.GetCoreConfigBackups)
	r.Post("/coreapps/{appID}/config/restore/{backup}", h.RestoreCoreConfigBackup)

	// NPM proxy hosts
	r.Get("/proxy-hosts", h.GetProxyHosts)

	return r
}

// GetStores returns all registered stores
func (h *AppStoreHandler) GetStores(w http.ResponseWriter, r *http.Request) {
	stores := h.manager.GetStores()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"stores": stores,
	})
}

// RegisterStore registers a new app store
func (h *AppStoreHandler) RegisterStore(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL         string `json:"url"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	if req.URL == "" {
		http.Error(w, `{"error":"url is required"}`, http.StatusBadRequest)
		return
	}

	store, err := h.manager.RegisterStore(req.URL, req.Name, req.Description)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	// Sync the new store
	go h.manager.SyncStore(store.ID)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(store)
}

// GetStore returns a specific store
func (h *AppStoreHandler) GetStore(w http.ResponseWriter, r *http.Request) {
	storeID := chi.URLParam(r, "storeID")
	store := h.manager.GetStore(storeID)
	if store == nil {
		http.Error(w, `{"error":"store not found"}`, http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(store)
}

// RemoveStore removes an app store
func (h *AppStoreHandler) RemoveStore(w http.ResponseWriter, r *http.Request) {
	storeID := chi.URLParam(r, "storeID")
	if err := h.manager.RemoveStore(storeID); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SyncStore syncs a specific store
func (h *AppStoreHandler) SyncStore(w http.ResponseWriter, r *http.Request) {
	storeID := chi.URLParam(r, "storeID")
	if err := h.manager.SyncStore(storeID); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	store := h.manager.GetStore(storeID)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"app_count": store.AppCount,
		"last_sync": store.LastSync,
	})
}

// SyncAllStores syncs all enabled stores
func (h *AppStoreHandler) SyncAllStores(w http.ResponseWriter, r *http.Request) {
	if err := h.manager.SyncAllStores(); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	stores := h.manager.GetStores()
	totalApps := 0
	for _, s := range stores {
		totalApps += s.AppCount
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":     true,
		"store_count": len(stores),
		"total_apps":  totalApps,
	})
}

// GetApps returns apps from the catalog
func (h *AppStoreHandler) GetApps(w http.ResponseWriter, r *http.Request) {
	category := r.URL.Query().Get("category")
	search := r.URL.Query().Get("search")
	storeID := r.URL.Query().Get("store_id")

	apps := h.manager.GetCatalog(category, search, storeID)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"apps":  apps,
		"count": len(apps),
	})
}

// GetCategories returns all categories
func (h *AppStoreHandler) GetCategories(w http.ResponseWriter, r *http.Request) {
	categories := h.manager.GetCategories()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"categories": categories,
	})
}

// GetApp returns a specific app from the catalog
func (h *AppStoreHandler) GetApp(w http.ResponseWriter, r *http.Request) {
	storeID := chi.URLParam(r, "storeID")
	appName := chi.URLParam(r, "appName")

	app := h.manager.GetApp(storeID, appName)
	if app == nil {
		http.Error(w, `{"error":"app not found"}`, http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(app)
}

// GetAppManifest returns the raw manifest for an app
func (h *AppStoreHandler) GetAppManifest(w http.ResponseWriter, r *http.Request) {
	storeID := chi.URLParam(r, "storeID")
	appName := chi.URLParam(r, "appName")

	manifest, err := h.manager.GetAppManifest(storeID, appName)
	if err != nil {
		http.Error(w, `{"error":"manifest not found"}`, http.StatusNotFound)
		return
	}

	format := r.URL.Query().Get("format")
	if format == "json" {
		// Parse and return as JSON
		var parsed models.CasaOSManifest
		if err := json.Unmarshal(manifest, &parsed); err == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(parsed)
			return
		}
	}

	w.Header().Set("Content-Type", "application/x-yaml")
	w.Write(manifest)
}

// GetAppIcon returns the icon for an app
func (h *AppStoreHandler) GetAppIcon(w http.ResponseWriter, r *http.Request) {
	storeID := chi.URLParam(r, "storeID")
	appName := chi.URLParam(r, "appName")

	iconPath := h.manager.GetIconPath(storeID, appName)
	if iconPath == "" {
		http.Error(w, "icon not found", http.StatusNotFound)
		return
	}

	data, err := os.ReadFile(iconPath)
	if err != nil {
		http.Error(w, "icon not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(data)
}

// GetAppScreenshot returns a screenshot for an app
func (h *AppStoreHandler) GetAppScreenshot(w http.ResponseWriter, r *http.Request) {
	storeID := chi.URLParam(r, "storeID")
	appName := chi.URLParam(r, "appName")
	indexStr := chi.URLParam(r, "index")

	index, err := strconv.Atoi(indexStr)
	if err != nil || index < 1 {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}

	ssPath := h.manager.GetScreenshotPath(storeID, appName, index)
	if ssPath == "" {
		http.Error(w, "screenshot not found", http.StatusNotFound)
		return
	}

	data, err := os.ReadFile(ssPath)
	if err != nil {
		http.Error(w, "screenshot not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(data)
}

// GetInstalledApps returns all installed apps
func (h *AppStoreHandler) GetInstalledApps(w http.ResponseWriter, r *http.Request) {
	apps := h.manager.GetInstalledApps()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"apps":  apps,
		"count": len(apps),
	})
}

// InstallApp installs an app from the store
func (h *AppStoreHandler) InstallApp(w http.ResponseWriter, r *http.Request) {
	var req models.AppInstallRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	if req.StoreID == "" || req.AppName == "" {
		http.Error(w, `{"error":"store_id and app_name are required"}`, http.StatusBadRequest)
		return
	}

	if !managers.ValidateAppName(req.AppName) {
		http.Error(w, `{"error":"invalid app name"}`, http.StatusBadRequest)
		return
	}

	app, err := h.manager.InstallApp(&req)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(app)
}

// GetInstalledApp returns a specific installed app
func (h *AppStoreHandler) GetInstalledApp(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")
	app := h.manager.GetInstalledApp(appID)
	if app == nil {
		http.Error(w, `{"error":"app not found"}`, http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(app)
}

// RemoveApp removes an installed app
func (h *AppStoreHandler) RemoveApp(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")
	deleteData := r.URL.Query().Get("delete_data") == "true"

	if err := h.manager.RemoveApp(appID, deleteData); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// StartApp starts an installed app
func (h *AppStoreHandler) StartApp(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")
	if err := h.manager.StartApp(appID); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

// StopApp stops an installed app
func (h *AppStoreHandler) StopApp(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")
	if err := h.manager.StopApp(appID); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

// RestartApp restarts an installed app
func (h *AppStoreHandler) RestartApp(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")
	if err := h.manager.RestartApp(appID); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

// AppAction performs an action on an installed app
func (h *AppStoreHandler) AppAction(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")

	var req models.AppActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	var err error
	switch req.Action {
	case "start":
		err = h.manager.StartApp(appID)
	case "stop":
		err = h.manager.StopApp(appID)
	case "restart":
		err = h.manager.RestartApp(appID)
	case "remove":
		err = h.manager.RemoveApp(appID, false)
	default:
		http.Error(w, `{"error":"invalid action"}`, http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

// ============================================================================
// Config Editor Handlers - User Apps (/cubeos/apps/)
// ============================================================================

// GetAppConfig returns the config files for an installed app
func (h *AppStoreHandler) GetAppConfig(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")

	config, err := h.manager.GetAppConfig(appID, false)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(config)
}

// UpdateAppConfig updates the config files for an installed app
func (h *AppStoreHandler) UpdateAppConfig(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")

	var req struct {
		ComposeYAML string `json:"compose_yaml"`
		EnvContent  string `json:"env_content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	if err := h.manager.UpdateAppConfig(appID, false, req.ComposeYAML, req.EnvContent); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Config saved. Use /config/apply to restart the app with new config.",
	})
}

// ApplyAppConfig applies config changes by restarting the app
func (h *AppStoreHandler) ApplyAppConfig(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")

	if err := h.manager.RestartAppWithConfig(appID, false); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "App restarted with new configuration",
	})
}

// GetConfigBackups returns available config backups for an app
func (h *AppStoreHandler) GetConfigBackups(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")

	backups, err := h.manager.GetConfigBackups(appID, false)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"backups": backups,
	})
}

// RestoreConfigBackup restores a config backup
func (h *AppStoreHandler) RestoreConfigBackup(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")
	backup := chi.URLParam(r, "backup")

	if err := h.manager.RestoreConfigBackup(appID, false, backup); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Backup restored. Use /config/apply to restart the app.",
	})
}

// ============================================================================
// Config Editor Handlers - Core Apps (/cubeos/coreapps/)
// ============================================================================

// ListCoreApps returns all core apps
func (h *AppStoreHandler) ListCoreApps(w http.ResponseWriter, r *http.Request) {
	apps, err := h.manager.ListCoreApps()
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"apps":    apps,
		"warning": "Core apps are system-critical. Modifying them may break your system.",
	})
}

// GetCoreAppConfig returns the config files for a core app
func (h *AppStoreHandler) GetCoreAppConfig(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")

	config, err := h.manager.GetAppConfig(appID, true)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"config":  config,
		"warning": "WARNING: This is a core system app. Incorrect changes may break your CubeOS installation!",
	})
}

// UpdateCoreAppConfig updates the config files for a core app
func (h *AppStoreHandler) UpdateCoreAppConfig(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")

	var req struct {
		ComposeYAML      string `json:"compose_yaml"`
		EnvContent       string `json:"env_content"`
		ConfirmDangerous bool   `json:"confirm_dangerous"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	if !req.ConfirmDangerous {
		http.Error(w, `{"error":"You must set confirm_dangerous=true to modify core app config","warning":"Modifying core apps may break your system!"}`, http.StatusBadRequest)
		return
	}

	if err := h.manager.UpdateAppConfig(appID, true, req.ComposeYAML, req.EnvContent); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Core app config saved. Use /config/apply to restart with new config.",
		"warning": "If the system becomes unresponsive, you may need physical access to recover.",
	})
}

// ApplyCoreAppConfig applies config changes by restarting a core app
func (h *AppStoreHandler) ApplyCoreAppConfig(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")

	var req struct {
		ConfirmDangerous bool `json:"confirm_dangerous"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
		if !req.ConfirmDangerous {
			http.Error(w, `{"error":"You must set confirm_dangerous=true to restart a core app"}`, http.StatusBadRequest)
			return
		}
	}

	if err := h.manager.RestartAppWithConfig(appID, true); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Core app restarted with new configuration",
	})
}

// GetCoreConfigBackups returns available config backups for a core app
func (h *AppStoreHandler) GetCoreConfigBackups(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")

	backups, err := h.manager.GetConfigBackups(appID, true)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"backups": backups,
	})
}

// RestoreCoreConfigBackup restores a config backup for a core app
func (h *AppStoreHandler) RestoreCoreConfigBackup(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")
	backup := chi.URLParam(r, "backup")

	if err := h.manager.RestoreConfigBackup(appID, true, backup); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Backup restored. Use /config/apply to restart the core app.",
	})
}

// ============================================================================
// NPM Proxy Hosts
// ============================================================================

// GetProxyHosts returns all NPM proxy hosts
func (h *AppStoreHandler) GetProxyHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := h.manager.GetNPMProxyHosts()
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"hosts": hosts,
	})
}

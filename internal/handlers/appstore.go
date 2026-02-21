package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"cubeos-api/internal/managers"
	"cubeos-api/internal/models"

	"github.com/go-chi/chi/v5"
)

// AppStoreHandler handles app store API requests
type AppStoreHandler struct {
	manager    *managers.AppStoreManager
	npmManager *managers.NPMManager
	jobTracker *managers.JobTracker
}

// NewAppStoreHandler creates a new app store handler
func NewAppStoreHandler(manager *managers.AppStoreManager, npmManager *managers.NPMManager) *AppStoreHandler {
	return &AppStoreHandler{
		manager:    manager,
		npmManager: npmManager,
		jobTracker: managers.NewJobTracker(),
	}
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

	// Job progress (SSE)
	r.Get("/jobs/{jobID}", h.JobProgress)

	// Config editor for user apps (/cubeos/apps/)
	r.Get("/installed/{appID}/config", h.GetAppConfig)
	r.Put("/installed/{appID}/config", h.UpdateAppConfig)
	r.Post("/installed/{appID}/config/apply", h.ApplyAppConfig)
	r.Get("/installed/{appID}/config/backups", h.GetConfigBackups)
	r.Post("/installed/{appID}/config/restore/{backup}", h.RestoreConfigBackup)

	// Volume management
	r.Get("/installed/{appID}/volumes", h.GetVolumeMappings)
	r.Put("/installed/{appID}/volumes", h.UpdateVolumeMappings)
	r.Get("/stores/{storeID}/apps/{appName}/volumes", h.PreviewVolumes)

	// Web UI behavior
	r.Put("/installed/{appID}/webui-type", h.UpdateWebUIType)

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

// ============================================================================
// Store Management Handlers
// ============================================================================

// GetStores godoc
// @Summary List all app stores
// @Description Returns all registered app stores including CasaOS-compatible stores
// @Tags AppStore - Stores
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "stores: array of store objects"
// @Router /appstore/stores [get]
func (h *AppStoreHandler) GetStores(w http.ResponseWriter, r *http.Request) {
	stores := h.manager.GetStores()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"stores": stores,
	})
}

// RegisterStore godoc
// @Summary Register a new app store
// @Description Registers a new app store URL and initiates background sync. Supports CasaOS-compatible store format.
// @Tags AppStore - Stores
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body object true "Store registration" SchemaExample({"url": "https://github.com/IceWhaleTech/CasaOS-AppStore", "name": "CasaOS Official", "description": "Official CasaOS app store"})
// @Success 201 {object} models.AppStore "Created store object"
// @Failure 400 {object} ErrorResponse "Invalid request or missing URL"
// @Failure 500 {object} ErrorResponse "Failed to register store"
// @Router /appstore/stores [post]
func (h *AppStoreHandler) RegisterStore(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL         string `json:"url"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if req.URL == "" {
		writeError(w, http.StatusBadRequest, "url is required")
		return
	}

	store, err := h.manager.RegisterStore(req.URL, req.Name, req.Description)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Sync the new store
	go h.manager.SyncStore(store.ID)

	writeJSON(w, http.StatusCreated, store)
}

// GetStore godoc
// @Summary Get a specific app store
// @Description Returns details of a specific app store by ID
// @Tags AppStore - Stores
// @Produce json
// @Security BearerAuth
// @Param storeID path string true "Store ID"
// @Success 200 {object} models.AppStore "Store details"
// @Failure 404 {object} ErrorResponse "Store not found"
// @Router /appstore/stores/{storeID} [get]
func (h *AppStoreHandler) GetStore(w http.ResponseWriter, r *http.Request) {
	storeID := chi.URLParam(r, "storeID")
	store := h.manager.GetStore(storeID)
	if store == nil {
		writeError(w, http.StatusNotFound, "store not found")
		return
	}
	writeJSON(w, http.StatusOK, store)
}

// RemoveStore godoc
// @Summary Remove an app store
// @Description Removes an app store from the registry. Does not affect already installed apps.
// @Tags AppStore - Stores
// @Security BearerAuth
// @Param storeID path string true "Store ID"
// @Success 204 "Store removed successfully"
// @Failure 500 {object} ErrorResponse "Failed to remove store"
// @Router /appstore/stores/{storeID} [delete]
func (h *AppStoreHandler) RemoveStore(w http.ResponseWriter, r *http.Request) {
	storeID := chi.URLParam(r, "storeID")
	if err := h.manager.RemoveStore(storeID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SyncStore godoc
// @Summary Sync a specific app store
// @Description Fetches latest app catalog from the specified store
// @Tags AppStore - Stores
// @Produce json
// @Security BearerAuth
// @Param storeID path string true "Store ID"
// @Success 200 {object} map[string]interface{} "success, app_count, last_sync"
// @Failure 500 {object} ErrorResponse "Sync failed"
// @Router /appstore/stores/{storeID}/sync [post]
func (h *AppStoreHandler) SyncStore(w http.ResponseWriter, r *http.Request) {
	storeID := chi.URLParam(r, "storeID")
	if err := h.manager.SyncStore(storeID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	store := h.manager.GetStore(storeID)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"app_count": store.AppCount,
		"last_sync": store.LastSync,
	})
}

// SyncAllStores godoc
// @Summary Sync all app stores
// @Description Fetches latest app catalogs from all enabled stores
// @Tags AppStore - Stores
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "success, store_count, total_apps"
// @Failure 500 {object} ErrorResponse "Sync failed"
// @Router /appstore/stores/sync [post]
func (h *AppStoreHandler) SyncAllStores(w http.ResponseWriter, r *http.Request) {
	if err := h.manager.SyncAllStores(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	stores := h.manager.GetStores()
	totalApps := 0
	for _, s := range stores {
		totalApps += s.AppCount
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":     true,
		"store_count": len(stores),
		"total_apps":  totalApps,
	})
}

// ============================================================================
// App Catalog Handlers
// ============================================================================

// GetApps godoc
// @Summary List apps from catalog
// @Description Returns apps from all stores with optional filtering by category, search term, or store
// @Tags AppStore - Catalog
// @Produce json
// @Security BearerAuth
// @Param category query string false "Filter by category"
// @Param search query string false "Search term for app name/description"
// @Param store_id query string false "Filter by specific store ID"
// @Success 200 {object} map[string]interface{} "apps: array of catalog apps, count: total"
// @Router /appstore/apps [get]
func (h *AppStoreHandler) GetApps(w http.ResponseWriter, r *http.Request) {
	category := r.URL.Query().Get("category")
	search := r.URL.Query().Get("search")
	storeID := r.URL.Query().Get("store_id")

	apps := h.manager.GetCatalog(category, search, storeID)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"apps":  apps,
		"count": len(apps),
	})
}

// GetCategories godoc
// @Summary List app categories
// @Description Returns all available app categories across all stores
// @Tags AppStore - Catalog
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "categories: array of category names"
// @Router /appstore/categories [get]
func (h *AppStoreHandler) GetCategories(w http.ResponseWriter, r *http.Request) {
	categories := h.manager.GetCategories()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"categories": categories,
	})
}

// GetApp godoc
// @Summary Get app details from catalog
// @Description Returns detailed information about a specific app in the catalog
// @Tags AppStore - Catalog
// @Produce json
// @Security BearerAuth
// @Param storeID path string true "Store ID"
// @Param appName path string true "App name"
// @Success 200 {object} models.StoreApp "App details"
// @Failure 404 {object} ErrorResponse "App not found"
// @Router /appstore/stores/{storeID}/apps/{appName} [get]
func (h *AppStoreHandler) GetApp(w http.ResponseWriter, r *http.Request) {
	storeID := chi.URLParam(r, "storeID")
	appName := chi.URLParam(r, "appName")

	app := h.manager.GetApp(storeID, appName)
	if app == nil {
		writeError(w, http.StatusNotFound, "app not found")
		return
	}
	writeJSON(w, http.StatusOK, app)
}

// GetAppManifest godoc
// @Summary Get app manifest
// @Description Returns the raw manifest (docker-compose) for an app. Supports YAML (default) or JSON format.
// @Tags AppStore - Catalog
// @Produce application/x-yaml,application/json
// @Security BearerAuth
// @Param storeID path string true "Store ID"
// @Param appName path string true "App name"
// @Param format query string false "Output format: yaml (default) or json"
// @Success 200 {object} models.CasaOSManifest "App manifest"
// @Failure 404 {object} ErrorResponse "Manifest not found"
// @Router /appstore/stores/{storeID}/apps/{appName}/manifest [get]
func (h *AppStoreHandler) GetAppManifest(w http.ResponseWriter, r *http.Request) {
	storeID := chi.URLParam(r, "storeID")
	appName := chi.URLParam(r, "appName")

	manifest, err := h.manager.GetAppManifest(storeID, appName)
	if err != nil {
		writeError(w, http.StatusNotFound, "manifest not found")
		return
	}

	format := r.URL.Query().Get("format")
	if format == "json" {
		// Parse and return as JSON
		var parsed models.CasaOSManifest
		if err := json.Unmarshal(manifest, &parsed); err == nil {
			writeJSON(w, http.StatusOK, parsed)
			return
		}
	}

	w.Header().Set("Content-Type", "application/x-yaml")
	w.Write(manifest)
}

// GetAppIcon godoc
// @Summary Get app icon
// @Description Returns the PNG icon for an app. Response is cached for 24 hours.
// @Tags AppStore - Catalog
// @Produce image/png
// @Security BearerAuth
// @Param storeID path string true "Store ID"
// @Param appName path string true "App name"
// @Success 200 {file} binary "PNG icon image"
// @Failure 404 {string} string "Icon not found"
// @Router /appstore/stores/{storeID}/apps/{appName}/icon [get]
func (h *AppStoreHandler) GetAppIcon(w http.ResponseWriter, r *http.Request) {
	storeID := chi.URLParam(r, "storeID")
	appName := chi.URLParam(r, "appName")

	iconPath := h.manager.GetIconPath(storeID, appName)
	if iconPath == "" {
		writeError(w, http.StatusNotFound, "icon not found")
		return
	}

	data, err := os.ReadFile(iconPath)
	if err != nil {
		writeError(w, http.StatusNotFound, "icon not found")
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(data)
}

// GetAppScreenshot godoc
// @Summary Get app screenshot
// @Description Returns a screenshot for an app by index (1-based). Response is cached for 24 hours.
// @Tags AppStore - Catalog
// @Produce image/png
// @Security BearerAuth
// @Param storeID path string true "Store ID"
// @Param appName path string true "App name"
// @Param index path integer true "Screenshot index (1-based)"
// @Success 200 {file} binary "PNG screenshot image"
// @Failure 400 {string} string "Invalid index"
// @Failure 404 {string} string "Screenshot not found"
// @Router /appstore/stores/{storeID}/apps/{appName}/screenshot/{index} [get]
func (h *AppStoreHandler) GetAppScreenshot(w http.ResponseWriter, r *http.Request) {
	storeID := chi.URLParam(r, "storeID")
	appName := chi.URLParam(r, "appName")
	indexStr := chi.URLParam(r, "index")

	index, err := strconv.Atoi(indexStr)
	if err != nil || index < 1 {
		writeError(w, http.StatusBadRequest, "invalid index")
		return
	}

	ssPath := h.manager.GetScreenshotPath(storeID, appName, index)
	if ssPath == "" {
		writeError(w, http.StatusNotFound, "screenshot not found")
		return
	}

	data, err := os.ReadFile(ssPath)
	if err != nil {
		writeError(w, http.StatusNotFound, "screenshot not found")
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(data)
}

// ============================================================================
// Installed Apps Handlers
// ============================================================================

// GetInstalledApps godoc
// @Summary List installed apps
// @Description Returns all apps installed from the app store
// @Tags AppStore - Installed
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "apps: array of installed apps, count: total"
// @Router /appstore/installed [get]
func (h *AppStoreHandler) GetInstalledApps(w http.ResponseWriter, r *http.Request) {
	apps := h.manager.GetInstalledApps()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"apps":  apps,
		"count": len(apps),
	})
}

// InstallApp godoc
// @Summary Install an app from store
// @Description Starts async app installation. Returns a job_id immediately. Use GET /appstore/jobs/{jobID} (SSE) to track progress.
// @Tags AppStore - Installed
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body models.AppInstallRequest true "Installation request"
// @Success 202 {object} map[string]interface{} "Job started: job_id, status"
// @Failure 400 {object} ErrorResponse "Invalid request, missing fields, or invalid app name"
// @Router /appstore/installed [post]
func (h *AppStoreHandler) InstallApp(w http.ResponseWriter, r *http.Request) {
	var req models.AppInstallRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if req.StoreID == "" || req.AppName == "" {
		writeError(w, http.StatusBadRequest, "store_id and app_name are required")
		return
	}

	if !managers.ValidateAppName(req.AppName) {
		writeError(w, http.StatusBadRequest, "invalid app name")
		return
	}

	if h.manager == nil {
		writeError(w, http.StatusInternalServerError, "app store manager not initialized")
		return
	}

	job := h.jobTracker.CreateJob("install", req.AppName)

	// Run install in background goroutine
	go func() {
		defer job.Close()

		installed, err := h.manager.InstallAppWithProgress(&req, job)
		if err != nil {
			job.EmitError("error", job.GetProgress(), err.Error())
			return
		}

		// Pass the app's access URL so the frontend "Open App" button works
		appURL := ""
		if installed != nil && installed.WebUI != "" {
			appURL = installed.WebUI
		}
		job.EmitDone("App installed successfully!", appURL)
	}()

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"job_id": job.ID,
		"status": "installing",
	})
}

// GetInstalledApp godoc
// @Summary Get installed app details
// @Description Returns details of a specific installed app including status and configuration
// @Tags AppStore - Installed
// @Produce json
// @Security BearerAuth
// @Param appID path string true "App ID"
// @Success 200 {object} models.InstalledApp "Installed app details"
// @Failure 404 {object} ErrorResponse "App not found"
// @Router /appstore/installed/{appID} [get]
func (h *AppStoreHandler) GetInstalledApp(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")
	app := h.manager.GetInstalledApp(appID)
	if app == nil {
		writeError(w, http.StatusNotFound, "app not found")
		return
	}
	writeJSON(w, http.StatusOK, app)
}

// RemoveApp godoc
// @Summary Uninstall an app
// @Description Starts async app removal. Returns a job_id immediately. Use GET /appstore/jobs/{jobID} (SSE) to track progress.
// @Tags AppStore - Installed
// @Security BearerAuth
// @Param appID path string true "App ID"
// @Param delete_data query boolean false "Also delete app data volumes"
// @Success 202 {object} map[string]interface{} "Job started: job_id, status"
// @Failure 500 {object} ErrorResponse "Removal failed"
// @Router /appstore/installed/{appID} [delete]
func (h *AppStoreHandler) RemoveApp(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")
	deleteData := r.URL.Query().Get("delete_data") == "true"

	if h.manager == nil {
		writeError(w, http.StatusInternalServerError, "app store manager not initialized")
		return
	}

	job := h.jobTracker.CreateJob("uninstall", appID)

	go func() {
		defer job.Close()

		if err := h.manager.RemoveAppWithProgress(appID, deleteData, job); err != nil {
			job.EmitError("error", job.GetProgress(), err.Error())
			return
		}

		job.EmitDone("App uninstalled successfully!")
	}()

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"job_id": job.ID,
		"status": "uninstalling",
	})
}

// JobProgress godoc
// @Summary Stream job progress via SSE
// @Description Opens a Server-Sent Events stream for a running install/uninstall job. Each event is a JSON ProgressEvent. The stream closes when the job completes or fails.
// @Tags AppStore - Jobs
// @Produce text/event-stream
// @Security BearerAuth
// @Param jobID path string true "Job ID returned from install/uninstall"
// @Success 200 {object} managers.ProgressEvent "SSE stream of progress events"
// @Failure 404 {object} ErrorResponse "Job not found"
// @Failure 500 {object} ErrorResponse "Streaming not supported"
// @Router /appstore/jobs/{jobID} [get]
func (h *AppStoreHandler) JobProgress(w http.ResponseWriter, r *http.Request) {
	jobID := chi.URLParam(r, "jobID")
	job := h.jobTracker.GetJob(jobID)
	if job == nil {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // Disable Nginx buffering (NPM reverse proxy)

	// Stream events until channel closes or client disconnects
	for {
		select {
		case event, ok := <-job.Events:
			if !ok {
				// Channel closed — job finished
				return
			}
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()

		case <-r.Context().Done():
			// Client disconnected
			return
		}
	}
}

// ============================================================================
// Volume Management Handlers
// ============================================================================

// GetVolumeMappings godoc
// @Summary Get volume mappings for an installed app
// @Description Returns current volume mount mappings showing original and remapped paths
// @Tags AppStore - Volumes
// @Produce json
// @Security BearerAuth
// @Param appID path string true "App ID"
// @Success 200 {object} managers.VolumeMappingsResponse "Volume mappings"
// @Failure 404 {object} ErrorResponse "App not found"
// @Failure 500 {object} ErrorResponse "Internal error"
// @Router /appstore/installed/{appID}/volumes [get]
func (h *AppStoreHandler) GetVolumeMappings(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")

	resp, err := h.manager.GetVolumeMappings(appID)
	if err != nil {
		if err.Error() == "app not found: "+appID {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// UpdateVolumeMappings godoc
// @Summary Update volume mappings for an installed app
// @Description Changes volume mount paths, rewrites compose file, and redeploys the stack
// @Tags AppStore - Volumes
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param appID path string true "App ID"
// @Param body body []managers.VolumeMappingUpdate true "Volume updates"
// @Success 200 {object} map[string]interface{} "success: true"
// @Failure 400 {object} ErrorResponse "Invalid request or path"
// @Failure 500 {object} ErrorResponse "Update failed"
// @Router /appstore/installed/{appID}/volumes [put]
func (h *AppStoreHandler) UpdateVolumeMappings(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")

	var updates []managers.VolumeMappingUpdate
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(updates) == 0 {
		writeError(w, http.StatusBadRequest, "no volume updates provided")
		return
	}

	if err := h.manager.UpdateVolumeMappings(appID, updates); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Updated %d volume mapping(s) and redeployed %s", len(updates), appID),
	})
}

// PreviewVolumes godoc
// @Summary Preview volume mappings for a store app before install
// @Description Analyzes the app manifest and shows which volumes would be remapped
// @Tags AppStore - Volumes
// @Produce json
// @Security BearerAuth
// @Param storeID path string true "Store ID"
// @Param appName path string true "App name"
// @Success 200 {object} managers.VolumePreviewResponse "Volume preview"
// @Failure 404 {object} ErrorResponse "App not found"
// @Failure 500 {object} ErrorResponse "Internal error"
// @Router /appstore/stores/{storeID}/apps/{appName}/volumes [get]
func (h *AppStoreHandler) PreviewVolumes(w http.ResponseWriter, r *http.Request) {
	storeID := chi.URLParam(r, "storeID")
	appName := chi.URLParam(r, "appName")

	resp, err := h.manager.PreviewVolumes(storeID, appName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// BrowseDirectories godoc
// @Summary Browse host directories
// @Description Lists subdirectories at a given path for the directory picker UI
// @Tags System
// @Produce json
// @Security BearerAuth
// @Param path query string false "Directory path to browse (default: /)"
// @Success 200 {object} map[string]interface{} "path, entries array"
// @Failure 400 {object} ErrorResponse "Invalid path"
// @Router /system/browse [get]
func (h *AppStoreHandler) BrowseDirectories(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		path = "/"
	}

	entries, err := managers.BrowseDirectories(path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"path":    path,
		"entries": entries,
	})
}

// StartApp godoc
// @Summary Start an installed app
// @Description Starts a stopped app's Docker containers
// @Tags AppStore - Installed
// @Produce json
// @Security BearerAuth
// @Param appID path string true "App ID"
// @Success 200 {object} map[string]bool "success: true"
// @Failure 500 {object} ErrorResponse "Start failed"
// @Router /appstore/installed/{appID}/start [post]
func (h *AppStoreHandler) StartApp(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")
	if err := h.manager.StartApp(appID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// StopApp godoc
// @Summary Stop an installed app
// @Description Stops a running app's Docker containers
// @Tags AppStore - Installed
// @Produce json
// @Security BearerAuth
// @Param appID path string true "App ID"
// @Success 200 {object} map[string]bool "success: true"
// @Failure 500 {object} ErrorResponse "Stop failed"
// @Router /appstore/installed/{appID}/stop [post]
func (h *AppStoreHandler) StopApp(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")
	if err := h.manager.StopApp(appID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// RestartApp godoc
// @Summary Restart an installed app
// @Description Restarts an app's Docker containers
// @Tags AppStore - Installed
// @Produce json
// @Security BearerAuth
// @Param appID path string true "App ID"
// @Success 200 {object} map[string]bool "success: true"
// @Failure 500 {object} ErrorResponse "Restart failed"
// @Router /appstore/installed/{appID}/restart [post]
func (h *AppStoreHandler) RestartApp(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")
	if err := h.manager.RestartApp(appID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// UpdateWebUIType godoc
// @Summary Set web UI click behavior
// @Description Sets whether clicking an app opens a browser tab or shows a status modal.
// @Description Auto-detected on install via Content-Type sniffing; this endpoint lets users override.
// @Tags AppStore - Installed
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param appID path string true "App ID"
// @Param request body object true "webui_type: 'browser' or 'api'"
// @Success 200 {object} map[string]interface{} "success, webui_type"
// @Failure 400 {object} ErrorResponse "Invalid type"
// @Failure 404 {object} ErrorResponse "App not found"
// @Router /appstore/installed/{appID}/webui-type [put]
func (h *AppStoreHandler) UpdateWebUIType(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")

	var req struct {
		WebUIType string `json:"webui_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if err := h.manager.UpdateWebUIType(appID, req.WebUIType); err != nil {
		errMsg := err.Error()
		if errMsg == "app not found: "+appID {
			writeError(w, http.StatusNotFound, errMsg)
		} else {
			writeError(w, http.StatusBadRequest, errMsg)
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":    true,
		"webui_type": req.WebUIType,
	})
}

// AppAction godoc
// @Summary Perform action on app
// @Description Performs a lifecycle action on an installed app (start, stop, restart, remove)
// @Tags AppStore - Installed
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param appID path string true "App ID"
// @Param request body models.AppActionRequest true "Action request"
// @Success 200 {object} map[string]bool "success: true"
// @Failure 400 {object} ErrorResponse "Invalid request or action"
// @Failure 500 {object} ErrorResponse "Action failed"
// @Router /appstore/installed/{appID}/action [post]
func (h *AppStoreHandler) AppAction(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")

	var req models.AppActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
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
		writeError(w, http.StatusBadRequest, "invalid action")
		return
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// ============================================================================
// Config Editor Handlers - User Apps (/cubeos/apps/)
// ============================================================================

// GetAppConfig godoc
// @Summary Get app configuration
// @Description Returns the docker-compose.yml and .env files for an installed user app
// @Tags AppStore - Config (User Apps)
// @Produce json
// @Security BearerAuth
// @Param appID path string true "App ID"
// @Success 200 {object} map[string]interface{} "App configuration files"
// @Failure 404 {object} ErrorResponse "App not found"
// @Router /appstore/installed/{appID}/config [get]
func (h *AppStoreHandler) GetAppConfig(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")

	config, err := h.manager.GetAppConfig(appID, false)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, config)
}

// UpdateAppConfig godoc
// @Summary Update app configuration
// @Description Updates the docker-compose.yml and/or .env files for a user app. Changes are saved but not applied until /config/apply is called.
// @Tags AppStore - Config (User Apps)
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param appID path string true "App ID"
// @Param request body object true "Config update" SchemaExample({"compose_yaml": "version: '3'...", "env_content": "KEY=value"})
// @Success 200 {object} map[string]interface{} "success, message"
// @Failure 400 {object} ErrorResponse "Invalid request"
// @Failure 500 {object} ErrorResponse "Update failed"
// @Router /appstore/installed/{appID}/config [put]
func (h *AppStoreHandler) UpdateAppConfig(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")

	var req struct {
		ComposeYAML string `json:"compose_yaml"`
		EnvContent  string `json:"env_content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if err := h.manager.UpdateAppConfig(appID, false, req.ComposeYAML, req.EnvContent); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Config saved. Use /config/apply to restart the app with new config.",
	})
}

// ApplyAppConfig godoc
// @Summary Apply app configuration changes
// @Description Restarts the app with the updated configuration files
// @Tags AppStore - Config (User Apps)
// @Produce json
// @Security BearerAuth
// @Param appID path string true "App ID"
// @Success 200 {object} map[string]interface{} "success, message"
// @Failure 500 {object} ErrorResponse "Apply failed"
// @Router /appstore/installed/{appID}/config/apply [post]
func (h *AppStoreHandler) ApplyAppConfig(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")

	if err := h.manager.RestartAppWithConfig(appID, false); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "App restarted with new configuration",
	})
}

// GetConfigBackups godoc
// @Summary List config backups
// @Description Returns available configuration backups for a user app
// @Tags AppStore - Config (User Apps)
// @Produce json
// @Security BearerAuth
// @Param appID path string true "App ID"
// @Success 200 {object} map[string]interface{} "backups: array of backup info"
// @Failure 500 {object} ErrorResponse "Failed to list backups"
// @Router /appstore/installed/{appID}/config/backups [get]
func (h *AppStoreHandler) GetConfigBackups(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")

	backups, err := h.manager.GetConfigBackups(appID, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"backups": backups,
	})
}

// RestoreConfigBackup godoc
// @Summary Restore config backup
// @Description Restores a configuration backup. Use /config/apply to restart with restored config.
// @Tags AppStore - Config (User Apps)
// @Produce json
// @Security BearerAuth
// @Param appID path string true "App ID"
// @Param backup path string true "Backup filename/identifier"
// @Success 200 {object} map[string]interface{} "success, message"
// @Failure 500 {object} ErrorResponse "Restore failed"
// @Router /appstore/installed/{appID}/config/restore/{backup} [post]
func (h *AppStoreHandler) RestoreConfigBackup(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")
	backup := chi.URLParam(r, "backup")

	if err := h.manager.RestoreConfigBackup(appID, false, backup); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Backup restored. Use /config/apply to restart the app.",
	})
}

// ============================================================================
// Config Editor Handlers - Core Apps (/cubeos/coreapps/)
// ============================================================================

// ListCoreApps godoc
// @Summary List core system apps
// @Description Returns all core system apps (pihole, npm, api, etc). WARNING: Modifying core apps may break your system.
// @Tags AppStore - Config (Core Apps)
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "apps: array of core apps, warning: safety message"
// @Failure 500 {object} ErrorResponse "Failed to list core apps"
// @Router /appstore/coreapps [get]
func (h *AppStoreHandler) ListCoreApps(w http.ResponseWriter, r *http.Request) {
	apps, err := h.manager.ListCoreApps()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"apps":    apps,
		"warning": "Core apps are system-critical. Modifying them may break your system.",
	})
}

// GetCoreAppConfig godoc
// @Summary Get core app configuration
// @Description Returns the docker-compose.yml and .env files for a core system app. WARNING: Core apps are system-critical.
// @Tags AppStore - Config (Core Apps)
// @Produce json
// @Security BearerAuth
// @Param appID path string true "Core app ID (e.g., pihole, npm, api)"
// @Success 200 {object} map[string]interface{} "config: app config, warning: safety message"
// @Failure 404 {object} ErrorResponse "Core app not found"
// @Router /appstore/coreapps/{appID}/config [get]
func (h *AppStoreHandler) GetCoreAppConfig(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")

	config, err := h.manager.GetAppConfig(appID, true)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"config":  config,
		"warning": "WARNING: This is a core system app. Incorrect changes may break your CubeOS installation!",
	})
}

// UpdateCoreAppConfig godoc
// @Summary Update core app configuration
// @Description Updates configuration for a core system app. Requires confirm_dangerous=true. WARNING: May break system!
// @Tags AppStore - Config (Core Apps)
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param appID path string true "Core app ID"
// @Param request body object true "Config update with confirmation" SchemaExample({"compose_yaml": "...", "env_content": "...", "confirm_dangerous": true})
// @Success 200 {object} map[string]interface{} "success, message, warning"
// @Failure 400 {object} ErrorResponse "Missing confirm_dangerous or invalid request"
// @Failure 500 {object} ErrorResponse "Update failed"
// @Router /appstore/coreapps/{appID}/config [put]
func (h *AppStoreHandler) UpdateCoreAppConfig(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")

	var req struct {
		ComposeYAML      string `json:"compose_yaml"`
		EnvContent       string `json:"env_content"`
		ConfirmDangerous bool   `json:"confirm_dangerous"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if !req.ConfirmDangerous {
		writeError(w, http.StatusBadRequest, "You must set confirm_dangerous=true to modify core app config")
		return
	}

	if err := h.manager.UpdateAppConfig(appID, true, req.ComposeYAML, req.EnvContent); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Core app config saved. Use /config/apply to restart with new config.",
		"warning": "If the system becomes unresponsive, you may need physical access to recover.",
	})
}

// ApplyCoreAppConfig godoc
// @Summary Apply core app configuration changes
// @Description Restarts a core system app with updated configuration. Requires confirm_dangerous=true.
// @Tags AppStore - Config (Core Apps)
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param appID path string true "Core app ID"
// @Param request body object false "Confirmation" SchemaExample({"confirm_dangerous": true})
// @Success 200 {object} map[string]interface{} "success, message"
// @Failure 400 {object} ErrorResponse "Missing confirm_dangerous"
// @Failure 500 {object} ErrorResponse "Apply failed"
// @Router /appstore/coreapps/{appID}/config/apply [post]
func (h *AppStoreHandler) ApplyCoreAppConfig(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")

	var req struct {
		ConfirmDangerous bool `json:"confirm_dangerous"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if !req.ConfirmDangerous {
		writeError(w, http.StatusBadRequest, "You must set confirm_dangerous=true to restart a core app")
		return
	}

	if err := h.manager.RestartAppWithConfig(appID, true); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Core app restarted with new configuration",
	})
}

// GetCoreConfigBackups godoc
// @Summary List core app config backups
// @Description Returns available configuration backups for a core system app
// @Tags AppStore - Config (Core Apps)
// @Produce json
// @Security BearerAuth
// @Param appID path string true "Core app ID"
// @Success 200 {object} map[string]interface{} "backups: array of backup info"
// @Failure 500 {object} ErrorResponse "Failed to list backups"
// @Router /appstore/coreapps/{appID}/config/backups [get]
func (h *AppStoreHandler) GetCoreConfigBackups(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")

	backups, err := h.manager.GetConfigBackups(appID, true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"backups": backups,
	})
}

// RestoreCoreConfigBackup godoc
// @Summary Restore core app config backup
// @Description Restores a configuration backup for a core app. Use /config/apply to restart with restored config.
// @Tags AppStore - Config (Core Apps)
// @Produce json
// @Security BearerAuth
// @Param appID path string true "Core app ID"
// @Param backup path string true "Backup filename/identifier"
// @Success 200 {object} map[string]interface{} "success, message"
// @Failure 500 {object} ErrorResponse "Restore failed"
// @Router /appstore/coreapps/{appID}/config/restore/{backup} [post]
func (h *AppStoreHandler) RestoreCoreConfigBackup(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appID")
	backup := chi.URLParam(r, "backup")

	if err := h.manager.RestoreConfigBackup(appID, true, backup); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Backup restored. Use /config/apply to restart the core app.",
	})
}

// ============================================================================
// NPM Proxy Hosts
// ============================================================================

// GetProxyHosts godoc
// @Summary List NPM proxy hosts
// @Description Returns all Nginx Proxy Manager proxy host configurations for installed apps
// @Tags AppStore - NPM
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "hosts: array of proxy host configs"
// @Failure 500 {object} ErrorResponse "Failed to fetch proxy hosts"
// @Router /appstore/proxy-hosts [get]
func (h *AppStoreHandler) GetProxyHosts(w http.ResponseWriter, r *http.Request) {
	// Use NPMManager which has proper token initialization
	if h.npmManager == nil || !h.npmManager.IsAuthenticated() {
		writeError(w, http.StatusServiceUnavailable, "NPM authentication not configured")
		return
	}

	hosts, err := h.npmManager.ListProxyHosts()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"hosts": hosts,
	})
}

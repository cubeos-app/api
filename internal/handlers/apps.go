// Package handlers provides HTTP handlers for CubeOS API.
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"cubeos-api/internal/managers"
	"cubeos-api/internal/models"
)

// AppsHandler handles unified app management endpoints.
type AppsHandler struct {
	orchestrator *managers.Orchestrator
}

// NewAppsHandler creates a new AppsHandler instance.
func NewAppsHandler(orchestrator *managers.Orchestrator) *AppsHandler {
	return &AppsHandler{
		orchestrator: orchestrator,
	}
}

// Routes returns the router for apps endpoints.
func (h *AppsHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Get("/", h.ListApps)
	r.Post("/", h.InstallApp)
	r.Get("/{name}", h.GetApp)
	r.Delete("/{name}", h.UninstallApp)

	// Lifecycle
	r.Post("/{name}/start", h.StartApp)
	r.Post("/{name}/stop", h.StopApp)
	r.Post("/{name}/restart", h.RestartApp)

	// Boot control
	r.Post("/{name}/enable", h.EnableApp)
	r.Post("/{name}/disable", h.DisableApp)

	// Logs
	r.Get("/{name}/logs", h.GetAppLogs)

	// Routing (Tor/VPN)
	r.Post("/{name}/tor", h.SetAppTor)
	r.Post("/{name}/vpn", h.SetAppVPN)

	return r
}

// ListApps godoc
// @Summary List all apps
// @Description Returns all apps with optional filtering by type and enabled state
// @Tags Apps
// @Produce json
// @Security BearerAuth
// @Param type query string false "Filter by app type (system, user)"
// @Param enabled query bool false "Filter by enabled state"
// @Success 200 {object} map[string]interface{} "List of apps"
// @Failure 500 {object} ErrorResponse "Failed to list apps"
// @Router /apps [get]
func (h *AppsHandler) ListApps(w http.ResponseWriter, r *http.Request) {
	filter := &models.AppFilter{}

	if t := r.URL.Query().Get("type"); t != "" {
		filter.Type = models.AppType(t)
	}
	if e := r.URL.Query().Get("enabled"); e != "" {
		enabled := e == "true"
		filter.Enabled = &enabled
	}

	apps, err := h.orchestrator.ListApps(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"apps": apps,
	})
}

// GetApp godoc
// @Summary Get app details
// @Description Returns details of a specific app by name
// @Tags Apps
// @Produce json
// @Security BearerAuth
// @Param name path string true "App name"
// @Success 200 {object} models.App "App details"
// @Failure 404 {object} ErrorResponse "App not found"
// @Failure 500 {object} ErrorResponse "Database error"
// @Router /apps/{name} [get]
func (h *AppsHandler) GetApp(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	app, err := h.orchestrator.GetApp(r.Context(), name)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	writeJSON(w, http.StatusOK, app)
}

// InstallApp godoc
// @Summary Install an app
// @Description Installs a new app from the app store or custom source
// @Tags Apps
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body models.InstallAppRequest true "App installation configuration"
// @Success 201 {object} models.App "Installed app details"
// @Failure 400 {object} ErrorResponse "Invalid request or missing name"
// @Failure 500 {object} ErrorResponse "Failed to install app"
// @Router /apps [post]
func (h *AppsHandler) InstallApp(w http.ResponseWriter, r *http.Request) {
	var req models.InstallAppRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "App name is required")
		return
	}

	app, err := h.orchestrator.InstallApp(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, app)
}

// UninstallApp godoc
// @Summary Uninstall an app
// @Description Removes an installed app with optional data retention
// @Tags Apps
// @Produce json
// @Security BearerAuth
// @Param name path string true "App name"
// @Param keep_data query bool false "Keep app data after uninstall" default(false)
// @Success 200 {object} map[string]interface{} "Uninstall confirmation"
// @Failure 404 {object} ErrorResponse "App not found"
// @Failure 500 {object} ErrorResponse "Failed to uninstall app"
// @Router /apps/{name} [delete]
func (h *AppsHandler) UninstallApp(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	keepData := r.URL.Query().Get("keep_data") == "true"

	// Check if app exists first
	if _, err := h.orchestrator.GetApp(r.Context(), name); err != nil {
		writeError(w, http.StatusNotFound, "App not found: "+name)
		return
	}

	if err := h.orchestrator.UninstallApp(r.Context(), name, keepData); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "App uninstalled successfully",
	})
}

// StartApp godoc
// @Summary Start an app
// @Description Starts a stopped app
// @Tags Apps
// @Produce json
// @Security BearerAuth
// @Param name path string true "App name"
// @Success 200 {object} map[string]interface{} "Start confirmation"
// @Failure 500 {object} ErrorResponse "Failed to start app"
// @Router /apps/{name}/start [post]
func (h *AppsHandler) StartApp(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	if err := h.orchestrator.StartApp(r.Context(), name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "App started",
	})
}

// StopApp godoc
// @Summary Stop an app
// @Description Stops a running app
// @Tags Apps
// @Produce json
// @Security BearerAuth
// @Param name path string true "App name"
// @Success 200 {object} map[string]interface{} "Stop confirmation"
// @Failure 500 {object} ErrorResponse "Failed to stop app"
// @Router /apps/{name}/stop [post]
func (h *AppsHandler) StopApp(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	if err := h.orchestrator.StopApp(r.Context(), name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "App stopped",
	})
}

// RestartApp godoc
// @Summary Restart an app
// @Description Restarts an app (stop then start)
// @Tags Apps
// @Produce json
// @Security BearerAuth
// @Param name path string true "App name"
// @Success 200 {object} map[string]interface{} "Restart confirmation"
// @Failure 500 {object} ErrorResponse "Failed to restart app"
// @Router /apps/{name}/restart [post]
func (h *AppsHandler) RestartApp(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	if err := h.orchestrator.RestartApp(r.Context(), name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "App restarted",
	})
}

// EnableApp godoc
// @Summary Enable app auto-start
// @Description Enables an app to start automatically on boot
// @Tags Apps
// @Produce json
// @Security BearerAuth
// @Param name path string true "App name"
// @Success 200 {object} map[string]interface{} "Enable confirmation"
// @Failure 500 {object} ErrorResponse "Failed to enable app"
// @Router /apps/{name}/enable [post]
func (h *AppsHandler) EnableApp(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	if err := h.orchestrator.EnableApp(r.Context(), name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "App enabled for boot",
	})
}

// DisableApp godoc
// @Summary Disable app auto-start
// @Description Disables an app from starting automatically on boot
// @Tags Apps
// @Produce json
// @Security BearerAuth
// @Param name path string true "App name"
// @Success 200 {object} map[string]interface{} "Disable confirmation"
// @Failure 500 {object} ErrorResponse "Failed to disable app"
// @Router /apps/{name}/disable [post]
func (h *AppsHandler) DisableApp(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	if err := h.orchestrator.DisableApp(r.Context(), name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "App disabled from boot",
	})
}

// GetAppLogs godoc
// @Summary Get app logs
// @Description Returns logs for a specific app
// @Tags Apps
// @Produce json
// @Security BearerAuth
// @Param name path string true "App name"
// @Param lines query int false "Number of log lines" default(100)
// @Param since query string false "Since timestamp (RFC3339)"
// @Success 200 {object} map[string]interface{} "App logs"
// @Failure 500 {object} ErrorResponse "Failed to get logs"
// @Router /apps/{name}/logs [get]
func (h *AppsHandler) GetAppLogs(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	lines := 100
	if l := r.URL.Query().Get("lines"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			lines = parsed
		}
	}

	var since time.Time
	if s := r.URL.Query().Get("since"); s != "" {
		if parsed, err := time.Parse(time.RFC3339, s); err == nil {
			since = parsed
		}
	}

	logs, err := h.orchestrator.GetAppLogs(r.Context(), name, lines, since)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"logs":  logs,
		"lines": len(logs),
	})
}

// SetAppTor godoc
// @Summary Configure Tor routing for app
// @Description Enables or disables Tor network routing for an app's traffic
// @Tags Apps
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param name path string true "App name"
// @Param request body object true "Tor enabled state" example({"enabled": true})
// @Success 200 {object} map[string]interface{} "Tor configuration updated"
// @Failure 400 {object} ErrorResponse "Invalid request body"
// @Failure 500 {object} ErrorResponse "Failed to configure Tor"
// @Router /apps/{name}/tor [post]
func (h *AppsHandler) SetAppTor(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.orchestrator.SetAppTor(r.Context(), name, req.Enabled); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":     true,
		"tor_enabled": req.Enabled,
	})
}

// SetAppVPN godoc
// @Summary Configure VPN routing for app
// @Description Enables or disables VPN routing for an app's traffic
// @Tags Apps
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param name path string true "App name"
// @Param request body object true "VPN enabled state" example({"enabled": true})
// @Success 200 {object} map[string]interface{} "VPN configuration updated"
// @Failure 400 {object} ErrorResponse "Invalid request body"
// @Failure 500 {object} ErrorResponse "Failed to configure VPN"
// @Router /apps/{name}/vpn [post]
func (h *AppsHandler) SetAppVPN(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.orchestrator.SetAppVPN(r.Context(), name, req.Enabled); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":     true,
		"vpn_enabled": req.Enabled,
	})
}

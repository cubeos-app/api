// Package handlers provides HTTP handlers for CubeOS API.
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
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

// ListApps returns all apps with optional filtering.
// GET /api/v1/apps?type=user&enabled=true
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

// GetApp returns a single app by name.
// GET /api/v1/apps/{name}
func (h *AppsHandler) GetApp(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	app, err := h.orchestrator.GetApp(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, app)
}

// InstallApp installs a new app.
// POST /api/v1/apps
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

// UninstallApp removes an app.
// DELETE /api/v1/apps/{name}?keep_data=false
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

// StartApp starts an app.
// POST /api/v1/apps/{name}/start
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

// StopApp stops an app.
// POST /api/v1/apps/{name}/stop
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

// RestartApp restarts an app.
// POST /api/v1/apps/{name}/restart
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

// EnableApp enables an app to start on boot.
// POST /api/v1/apps/{name}/enable
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

// DisableApp disables an app from starting on boot.
// POST /api/v1/apps/{name}/disable
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

// GetAppLogs returns logs for an app.
// GET /api/v1/apps/{name}/logs?lines=100&since=2026-01-31T00:00:00Z
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

// SetAppTor enables/disables Tor routing for an app.
// POST /api/v1/apps/{name}/tor
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

// SetAppVPN enables/disables VPN routing for an app.
// POST /api/v1/apps/{name}/vpn
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

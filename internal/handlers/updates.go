package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"cubeos-api/internal/flowengine"
	"cubeos-api/internal/flowengine/workflows"
	"cubeos-api/internal/managers"
	"cubeos-api/internal/models"
)

// UpdatesHandler handles system update endpoints.
type UpdatesHandler struct {
	updateMgr  *managers.UpdateManager
	flowEngine *flowengine.WorkflowEngine
	db         *sql.DB
}

// NewUpdatesHandler creates a new UpdatesHandler instance.
func NewUpdatesHandler(mgr *managers.UpdateManager, engine *flowengine.WorkflowEngine, db *sql.DB) *UpdatesHandler {
	return &UpdatesHandler{
		updateMgr:  mgr,
		flowEngine: engine,
		db:         db,
	}
}

// Routes returns the router for update endpoints.
func (h *UpdatesHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Get("/", h.CheckUpdates)
	r.Post("/apply", h.ApplyUpdate)
	r.Get("/history", h.GetHistory)

	return r
}

// CheckUpdates godoc
// @Summary Check for system updates
// @Description Checks for available CubeOS system updates. Returns current version, latest available version, and release details. Works offline using cached data.
// @Tags System
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.UpdateCheckResponse "Update check result"
// @Failure 500 {object} models.ErrorResponse "Failed to check for updates"
// @Router /system/updates [get]
func (h *UpdatesHandler) CheckUpdates(w http.ResponseWriter, r *http.Request) {
	resp, err := h.updateMgr.CheckForUpdates(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// ApplyUpdate godoc
// @Summary Apply a system update
// @Description Submits a system update workflow to apply the specified version. Returns 202 Accepted with a workflow_id for progress tracking via GET /api/v1/workflows/{id}. If the update contains breaking changes and force is not set, returns 409 Conflict with the list of breaking changes.
// @Tags System
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body models.UpdateApplyRequest true "Update apply request"
// @Success 202 {object} map[string]string "Workflow submitted"
// @Failure 400 {object} models.ErrorResponse "Invalid request or version not found"
// @Failure 409 {object} map[string]interface{} "Breaking changes require force flag"
// @Failure 500 {object} models.ErrorResponse "Failed to submit update workflow"
// @Router /system/updates/apply [post]
func (h *UpdatesHandler) ApplyUpdate(w http.ResponseWriter, r *http.Request) {
	var req models.UpdateApplyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Version == "" {
		writeError(w, http.StatusBadRequest, "version is required")
		return
	}

	// Get the manifest for the requested version
	manifest := h.updateMgr.GetLatestRelease()
	if manifest == nil {
		writeError(w, http.StatusBadRequest, "no release manifest available — run an update check first")
		return
	}
	if manifest.Version != req.Version {
		writeError(w, http.StatusBadRequest, "requested version does not match latest available release")
		return
	}

	// Validate compatibility
	if err := h.updateMgr.ValidateUpdate(manifest); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Check breaking changes — return 409 if not forced
	if len(manifest.Breaking) > 0 && !req.Force {
		writeJSON(w, http.StatusConflict, map[string]interface{}{
			"error":            "update contains breaking changes",
			"breaking_changes": manifest.Breaking,
			"hint":             "set force=true to proceed",
		})
		return
	}

	// Build workflow input (fat envelope seed)
	workflowInput := map[string]interface{}{
		"version":  req.Version,
		"force":    req.Force,
		"manifest": manifest,
	}
	inputJSON, err := json.Marshal(workflowInput)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to marshal workflow input")
		return
	}

	// Submit workflow
	wf, err := h.flowEngine.Submit(r.Context(), flowengine.SubmitParams{
		WorkflowType: workflows.SystemUpdateType,
		ExternalID:   "system-update-" + req.Version,
		Input:        inputJSON,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{
		"workflow_id": wf.ID,
		"message":     "system update workflow submitted",
	})
}

// GetHistory godoc
// @Summary Get update history
// @Description Returns the history of system update attempts, ordered by most recent first. Limited to 50 entries.
// @Tags System
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string][]models.UpdateHistoryEntry "Update history"
// @Failure 500 {object} models.ErrorResponse "Failed to retrieve update history"
// @Router /system/updates/history [get]
func (h *UpdatesHandler) GetHistory(w http.ResponseWriter, r *http.Request) {
	entries, err := h.updateMgr.GetUpdateHistory(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if entries == nil {
		entries = []models.UpdateHistoryEntry{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"history": entries,
	})
}

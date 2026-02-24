package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"cubeos-api/internal/flowengine"
	feworkflows "cubeos-api/internal/flowengine/workflows"
	"cubeos-api/internal/hal"
	"cubeos-api/internal/managers"
	"cubeos-api/internal/models"
)

// BackupsHandler handles backup management endpoints
type BackupsHandler struct {
	backup       *managers.BackupManager
	flowEngine   *flowengine.WorkflowEngine
	feStore      *flowengine.WorkflowStore
	halClient    *hal.Client
	destRegistry *managers.BackupDestinationRegistry
}

// NewBackupsHandler creates a new backups handler wired to the BackupManager
func NewBackupsHandler(backup *managers.BackupManager, halClient *hal.Client, destRegistry *managers.BackupDestinationRegistry) *BackupsHandler {
	return &BackupsHandler{
		backup:       backup,
		halClient:    halClient,
		destRegistry: destRegistry,
	}
}

// SetFlowEngine wires the FlowEngine for async backup/restore. Called from main.go.
func (h *BackupsHandler) SetFlowEngine(engine *flowengine.WorkflowEngine, store *flowengine.WorkflowStore) {
	h.flowEngine = engine
	h.feStore = store
}

// Routes returns the backups routes
func (h *BackupsHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Get("/", h.ListBackups)
	r.Post("/", h.CreateBackup)
	r.Get("/stats", h.GetBackupStats)
	r.Post("/quick", h.QuickBackup)
	r.Get("/destinations", h.ListDestinations)
	r.Post("/destinations/test", h.TestDestination)
	r.Get("/{backup_id}", h.GetBackup)
	r.Delete("/{backup_id}", h.DeleteBackup)
	r.Get("/{backup_id}/download", h.DownloadBackup)
	r.Post("/{backup_id}/restore", h.RestoreBackup)
	r.Post("/{backup_id}/verify", h.VerifyBackup)

	return r
}

// ListBackups godoc
// @Summary List all backups
// @Description Returns a list of all available backups with total size
// @Tags Backup
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.BackupListResponse "Backup list"
// @Failure 500 {object} models.ErrorResponse "Failed to list backups"
// @Router /backups [get]
func (h *BackupsHandler) ListBackups(w http.ResponseWriter, r *http.Request) {
	backups := h.backup.ListBackups()
	totalSize := h.backup.GetTotalSize()

	writeJSON(w, http.StatusOK, models.BackupListResponse{
		Backups:        backups,
		TotalCount:     len(backups),
		TotalSizeBytes: totalSize,
	})
}

// CreateBackup godoc
// @Summary Create a new backup
// @Description Creates a new backup via FlowEngine workflow. Accepts enhanced request with scope and destination.
// @Tags Backup
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body models.BackupCreateEnhancedRequest false "Backup configuration (scope: tier1/tier2/tier3, destination: local)"
// @Success 202 {object} map[string]string "Backup workflow submitted"
// @Failure 400 {object} models.ErrorResponse "Invalid request"
// @Failure 500 {object} models.ErrorResponse "Failed to submit backup workflow"
// @Router /backups [post]
func (h *BackupsHandler) CreateBackup(w http.ResponseWriter, r *http.Request) {
	var req models.BackupCreateEnhancedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Fallback: try legacy request format
		req.Scope = models.BackupScopeTier1
		req.Destination = models.BackupDestLocal
	}

	// Default scope
	if req.Scope == "" {
		req.Scope = models.BackupScopeTier1
	}
	if req.Destination == "" {
		req.Destination = models.BackupDestLocal
	}

	// If FlowEngine is not available, fallback to synchronous backup
	if h.flowEngine == nil {
		backupType := "config"
		switch req.Scope {
		case models.BackupScopeTier2:
			backupType = "full"
		case models.BackupScopeTier3:
			backupType = "full"
		}
		result, err := h.backup.CreateBackup(backupType, req.Description, req.Scope == models.BackupScopeTier3, true)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, result)
		return
	}

	// Submit backup workflow via FlowEngine
	workflowInput := feworkflows.BackupInput{
		Scope:       string(req.Scope),
		Destination: string(req.Destination),
		DestConfig:  req.DestConfig,
		Description: req.Description,
		Encrypt:     req.Encrypt,
		Passphrase:  req.Passphrase,
	}

	inputJSON, err := json.Marshal(workflowInput)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to marshal workflow input")
		return
	}

	wf, err := h.flowEngine.Submit(r.Context(), flowengine.SubmitParams{
		WorkflowType: feworkflows.BackupWorkflowType,
		ExternalID:   "backup-" + string(req.Scope),
		Input:        inputJSON,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to submit backup workflow: "+err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{
		"status":      "accepted",
		"workflow_id": wf.ID,
		"message":     "Backup workflow submitted",
	})
}

// GetBackupStats godoc
// @Summary Get backup statistics
// @Description Returns statistics about backups including total count, size, and breakdown by type
// @Tags Backup
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Backup statistics"
// @Failure 500 {object} models.ErrorResponse "Failed to get backup stats"
// @Router /backups/stats [get]
func (h *BackupsHandler) GetBackupStats(w http.ResponseWriter, r *http.Request) {
	stats := h.backup.GetStats()
	writeJSON(w, http.StatusOK, stats)
}

// QuickBackup godoc
// @Summary Create a quick backup
// @Description Creates a quick backup with default settings (config-only, compressed, auto-named). Uses synchronous path for backward compatibility.
// @Tags Backup
// @Produce json
// @Security BearerAuth
// @Param backup_type query string false "Backup type" default(config)
// @Param description query string false "Backup description"
// @Success 200 {object} models.SuccessResponse "Backup created"
// @Failure 500 {object} models.ErrorResponse "Failed to create backup"
// @Router /backups/quick [post]
func (h *BackupsHandler) QuickBackup(w http.ResponseWriter, r *http.Request) {
	backupType := r.URL.Query().Get("backup_type")
	if backupType == "" {
		backupType = "config"
	}
	description := r.URL.Query().Get("description")
	if description == "" {
		description = "Quick " + backupType + " backup"
	}

	result, err := h.backup.CreateBackup(backupType, description, false, true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// GetBackup godoc
// @Summary Get backup details
// @Description Returns details for a specific backup
// @Tags Backup
// @Produce json
// @Security BearerAuth
// @Param backup_id path string true "Backup ID"
// @Success 200 {object} models.BackupInfo "Backup details"
// @Failure 404 {object} models.ErrorResponse "Backup not found"
// @Router /backups/{backup_id} [get]
func (h *BackupsHandler) GetBackup(w http.ResponseWriter, r *http.Request) {
	backupID := chi.URLParam(r, "backup_id")
	if backupID == "" {
		writeError(w, http.StatusBadRequest, "Backup ID is required")
		return
	}

	backup := h.backup.GetBackup(backupID)
	if backup == nil {
		writeError(w, http.StatusNotFound, "Backup not found")
		return
	}
	writeJSON(w, http.StatusOK, backup)
}

// DeleteBackup godoc
// @Summary Delete a backup
// @Description Permanently deletes a backup file and its metadata
// @Tags Backup
// @Produce json
// @Security BearerAuth
// @Param backup_id path string true "Backup ID"
// @Success 200 {object} models.SuccessResponse "Backup deleted"
// @Failure 404 {object} models.ErrorResponse "Backup not found"
// @Router /backups/{backup_id} [delete]
func (h *BackupsHandler) DeleteBackup(w http.ResponseWriter, r *http.Request) {
	backupID := chi.URLParam(r, "backup_id")
	if backupID == "" {
		writeError(w, http.StatusBadRequest, "Backup ID is required")
		return
	}

	result := h.backup.DeleteBackup(backupID)
	if result.Status == "error" {
		writeError(w, http.StatusNotFound, result.Message)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// DownloadBackup godoc
// @Summary Download a backup
// @Description Downloads a backup file as a gzip archive
// @Tags Backup
// @Produce application/gzip
// @Security BearerAuth
// @Param backup_id path string true "Backup ID"
// @Success 200 {file} binary "Backup file"
// @Failure 404 {object} models.ErrorResponse "Backup not found"
// @Router /backups/{backup_id}/download [get]
func (h *BackupsHandler) DownloadBackup(w http.ResponseWriter, r *http.Request) {
	backupID := chi.URLParam(r, "backup_id")
	if backupID == "" {
		writeError(w, http.StatusBadRequest, "Backup ID is required")
		return
	}

	backup := h.backup.GetBackup(backupID)
	if backup == nil {
		writeError(w, http.StatusNotFound, "Backup not found")
		return
	}

	filePath := h.backup.GetBackupFilePath(backupID)
	if filePath == "" {
		writeError(w, http.StatusNotFound, "Backup file not found")
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename="+backup.Filename)
	w.Header().Set("Content-Type", "application/gzip")
	http.ServeFile(w, r, filePath)
}

// RestoreBackup godoc
// @Summary Restore from a backup
// @Description Restores the system from a backup via FlowEngine workflow. Requires confirm=true query parameter.
// @Tags Backup
// @Produce json
// @Security BearerAuth
// @Param backup_id path string true "Backup ID"
// @Param confirm query bool true "Confirmation flag" example(true)
// @Success 202 {object} map[string]string "Restore workflow submitted"
// @Failure 400 {object} models.ErrorResponse "Confirmation required"
// @Failure 404 {object} models.ErrorResponse "Backup not found"
// @Failure 500 {object} models.ErrorResponse "Failed to submit restore workflow"
// @Router /backups/{backup_id}/restore [post]
func (h *BackupsHandler) RestoreBackup(w http.ResponseWriter, r *http.Request) {
	backupID := chi.URLParam(r, "backup_id")
	if backupID == "" {
		writeError(w, http.StatusBadRequest, "Backup ID is required")
		return
	}

	confirm := r.URL.Query().Get("confirm") == "true"
	if !confirm {
		writeError(w, http.StatusBadRequest, "Set confirm=true to restore")
		return
	}

	backup := h.backup.GetBackup(backupID)
	if backup == nil {
		writeError(w, http.StatusNotFound, "Backup not found")
		return
	}

	backupPath := h.backup.GetBackupFilePath(backupID)
	if backupPath == "" {
		writeError(w, http.StatusNotFound, "Backup file not found")
		return
	}

	// If FlowEngine is not available, fallback to synchronous restore
	if h.flowEngine == nil {
		restartServices := r.URL.Query().Get("restart_services") != "false"
		result, err := h.backup.RestoreBackup(backupID, restartServices)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, result)
		return
	}

	// Submit restore workflow
	workflowInput := feworkflows.RestoreInput{
		BackupID:   backupID,
		BackupPath: backupPath,
		Confirm:    true,
	}

	inputJSON, err := json.Marshal(workflowInput)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to marshal workflow input")
		return
	}

	wf, err := h.flowEngine.Submit(r.Context(), flowengine.SubmitParams{
		WorkflowType: feworkflows.RestoreWorkflowType,
		ExternalID:   "restore-" + backupID,
		Input:        inputJSON,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to submit restore workflow: "+err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{
		"status":      "accepted",
		"workflow_id": wf.ID,
		"message":     "Restore workflow submitted",
	})
}

// VerifyBackup godoc
// @Summary Verify backup integrity
// @Description Reads a backup archive and verifies integrity against its embedded manifest
// @Tags Backup
// @Produce json
// @Security BearerAuth
// @Param backup_id path string true "Backup ID"
// @Success 200 {object} models.BackupManifest "Backup manifest with verification result"
// @Failure 404 {object} models.ErrorResponse "Backup not found"
// @Failure 500 {object} models.ErrorResponse "Verification failed"
// @Router /backups/{backup_id}/verify [post]
func (h *BackupsHandler) VerifyBackup(w http.ResponseWriter, r *http.Request) {
	backupID := chi.URLParam(r, "backup_id")
	if backupID == "" {
		writeError(w, http.StatusBadRequest, "Backup ID is required")
		return
	}

	backupPath := h.backup.GetBackupFilePath(backupID)
	if backupPath == "" {
		writeError(w, http.StatusNotFound, "Backup not found")
		return
	}

	manifest, err := h.backup.VerifyBackup(backupPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Verification failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "verified",
		"manifest": manifest,
	})
}

// ListDestinations godoc
// @Summary List available backup destinations
// @Description Returns a list of available backup destinations. Local is always available. USB shown if detected. NFS/SMB always listed as options.
// @Tags Backup
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.BackupDestinationsResponse "Available destinations"
// @Failure 500 {object} models.ErrorResponse "Failed to list destinations"
// @Router /backups/destinations [get]
func (h *BackupsHandler) ListDestinations(w http.ResponseWriter, r *http.Request) {
	destinations := []models.BackupDestinationInfo{
		{
			Type:        string(models.BackupDestLocal),
			Name:        "Local Storage",
			Description: "Store backups on the local filesystem (/cubeos/data/backups/)",
			Available:   true,
		},
	}

	// Check USB availability via HAL
	usbAvailable := false
	if h.halClient != nil {
		devices, err := h.halClient.GetUSBStorageDevices(r.Context())
		if err == nil && len(devices) > 0 {
			usbAvailable = true
			for _, d := range devices {
				destinations = append(destinations, models.BackupDestinationInfo{
					Type:        string(models.BackupDestUSB),
					Name:        "USB: " + d.Name,
					Description: d.Model + " (" + d.SizeHuman + ")",
					Available:   true,
					Config: map[string]string{
						"device": d.Path,
					},
				})
			}
		}
	}

	// USB type without specific device (if no devices detected)
	if !usbAvailable {
		destinations = append(destinations, models.BackupDestinationInfo{
			Type:        string(models.BackupDestUSB),
			Name:        "USB Storage",
			Description: "Store backups on a USB drive (no USB storage detected)",
			Available:   false,
		})
	}

	// NFS and SMB are always listed as options
	destinations = append(destinations,
		models.BackupDestinationInfo{
			Type:        string(models.BackupDestNFS),
			Name:        "NFS Share",
			Description: "Store backups on a remote NFS share",
			Available:   true,
		},
		models.BackupDestinationInfo{
			Type:        string(models.BackupDestSMB),
			Name:        "SMB/CIFS Share",
			Description: "Store backups on a remote SMB/CIFS share (Windows, Samba, NAS)",
			Available:   true,
		},
	)

	writeJSON(w, http.StatusOK, models.BackupDestinationsResponse{
		Destinations: destinations,
	})
}

// TestDestination godoc
// @Summary Test a backup destination
// @Description Tests connectivity and write access to a backup destination. Validates the configuration without creating a backup.
// @Tags Backup
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body models.BackupDestinationTestRequest true "Destination test configuration"
// @Success 200 {object} models.BackupDestinationTestResponse "Test result"
// @Failure 400 {object} models.ErrorResponse "Invalid request"
// @Failure 500 {object} models.ErrorResponse "Test failed"
// @Router /backups/destinations/test [post]
func (h *BackupsHandler) TestDestination(w http.ResponseWriter, r *http.Request) {
	var req models.BackupDestinationTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}

	if req.Destination == "" {
		writeError(w, http.StatusBadRequest, "destination is required")
		return
	}

	if h.destRegistry == nil {
		writeError(w, http.StatusInternalServerError, "Destination registry not initialized")
		return
	}

	dest := models.BackupDestination(req.Destination)
	adapter, err := h.destRegistry.Get(dest)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Unsupported destination: "+string(dest))
		return
	}

	ctx := r.Context()
	resp := models.BackupDestinationTestResponse{
		Destination: req.Destination,
	}

	// Test validation
	if err := adapter.Validate(ctx, req.Config); err != nil {
		resp.Success = false
		resp.Message = "Validation failed: " + err.Error()
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// Check available space
	space, err := adapter.AvailableSpace(ctx, req.Config)
	if err == nil && space >= 0 {
		resp.AvailableSpace = space
	}

	resp.Success = true
	resp.Message = "Destination is accessible and writable"
	writeJSON(w, http.StatusOK, resp)
}

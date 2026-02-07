package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"cubeos-api/internal/managers"
	"cubeos-api/internal/models"
)

// BackupsHandler handles backup management endpoints
type BackupsHandler struct {
	backup *managers.BackupManager
}

// NewBackupsHandler creates a new backups handler wired to the BackupManager
func NewBackupsHandler(backup *managers.BackupManager) *BackupsHandler {
	return &BackupsHandler{
		backup: backup,
	}
}

// Routes returns the backups routes
func (h *BackupsHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Get("/", h.ListBackups)
	r.Post("/", h.CreateBackup)
	r.Get("/stats", h.GetBackupStats)
	r.Post("/quick", h.QuickBackup)
	r.Get("/{backup_id}", h.GetBackup)
	r.Delete("/{backup_id}", h.DeleteBackup)
	r.Get("/{backup_id}/download", h.DownloadBackup)
	r.Post("/{backup_id}/restore", h.RestoreBackup)

	return r
}

// ListBackups godoc
// @Summary List all backups
// @Description Returns a list of all available backups with total size
// @Tags Backups
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
// @Description Creates a new backup with the specified configuration
// @Tags Backups
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body models.BackupCreateRequest false "Backup configuration"
// @Success 200 {object} models.SuccessResponse "Backup created"
// @Failure 500 {object} models.ErrorResponse "Failed to create backup"
// @Router /backups [post]
func (h *BackupsHandler) CreateBackup(w http.ResponseWriter, r *http.Request) {
	var req models.BackupCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Use defaults on decode failure
		req.Type = "config"
		req.Compress = true
	}

	if req.Type == "" {
		req.Type = "config"
	}

	result, err := h.backup.CreateBackup(req.Type, req.Description, req.IncludeDockerVolumes, req.Compress)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// GetBackupStats godoc
// @Summary Get backup statistics
// @Description Returns statistics about backups including total count, size, and breakdown by type
// @Tags Backups
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
// @Description Creates a quick backup with default settings (config-only, compressed, auto-named)
// @Tags Backups
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
// @Tags Backups
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
// @Tags Backups
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
// @Tags Backups
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
// @Description Restores the system from a backup. Requires confirm=true query parameter.
// @Tags Backups
// @Produce json
// @Security BearerAuth
// @Param backup_id path string true "Backup ID"
// @Param confirm query bool true "Confirmation flag" example(true)
// @Param restart_services query bool false "Restart services after restore" default(true)
// @Success 200 {object} models.SuccessResponse "Backup restored"
// @Failure 400 {object} models.ErrorResponse "Confirmation required"
// @Failure 404 {object} models.ErrorResponse "Backup not found"
// @Failure 500 {object} models.ErrorResponse "Failed to restore backup"
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

	restartServices := r.URL.Query().Get("restart_services") != "false"

	result, err := h.backup.RestoreBackup(backupID, restartServices)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

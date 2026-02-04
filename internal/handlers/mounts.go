// Package handlers provides HTTP handlers for mount management.
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"cubeos-api/internal/managers"
	"cubeos-api/internal/models"
)

// MountsHandler handles mount-related HTTP requests
type MountsHandler struct {
	mounts *managers.MountsManager
}

// NewMountsHandler creates a new mounts handler
func NewMountsHandler(mounts *managers.MountsManager) *MountsHandler {
	return &MountsHandler{mounts: mounts}
}

// Routes returns the mounts router
func (h *MountsHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Get("/", h.ListMounts)
	r.Post("/", h.AddMount)
	r.Get("/{name}", h.GetMount)
	r.Delete("/{name}", h.DeleteMount)
	r.Post("/{name}/mount", h.Mount)
	r.Post("/{name}/unmount", h.Unmount)
	r.Get("/{name}/status", h.GetMountStatus)
	r.Post("/test", h.TestConnection)

	return r
}

// ListMounts godoc
// @Summary List all configured mounts
// @Description Returns all configured SMB and NFS network mounts with their current status
// @Tags Mounts
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "mounts: array of mount configurations"
// @Failure 500 {object} ErrorResponse "MOUNTS_LIST_ERROR"
// @Router /mounts [get]
func (h *MountsHandler) ListMounts(w http.ResponseWriter, r *http.Request) {
	mounts, err := h.mounts.ListMounts(r.Context())
	if err != nil {
		mountsRespondError(w, http.StatusInternalServerError, "MOUNTS_LIST_ERROR", err.Error())
		return
	}

	mountsRespondJSON(w, http.StatusOK, map[string]interface{}{
		"mounts": mounts,
	})
}

// GetMount godoc
// @Summary Get a specific mount configuration
// @Description Returns details of a specific mount configuration by name
// @Tags Mounts
// @Produce json
// @Security BearerAuth
// @Param name path string true "Mount name"
// @Success 200 {object} models.Mount "Mount configuration details"
// @Failure 400 {object} ErrorResponse "INVALID_NAME - Mount name is required"
// @Failure 404 {object} ErrorResponse "MOUNT_NOT_FOUND - Mount not found"
// @Router /mounts/{name} [get]
func (h *MountsHandler) GetMount(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		mountsRespondError(w, http.StatusBadRequest, "INVALID_NAME", "Mount name is required")
		return
	}

	mount, err := h.mounts.GetMountByName(r.Context(), name)
	if err != nil {
		mountsRespondError(w, http.StatusNotFound, "MOUNT_NOT_FOUND", err.Error())
		return
	}

	mountsRespondJSON(w, http.StatusOK, mount)
}

// AddMount godoc
// @Summary Add a new mount configuration
// @Description Creates a new SMB or NFS mount configuration. Does not mount automatically unless auto_mount is set.
// @Tags Mounts
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body managers.CreateMountRequest true "Mount configuration"
// @Success 201 {object} models.Mount "Created mount configuration"
// @Failure 400 {object} ErrorResponse "INVALID_JSON or MOUNT_ADD_ERROR"
// @Router /mounts [post]
func (h *MountsHandler) AddMount(w http.ResponseWriter, r *http.Request) {
	var req managers.CreateMountRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mountsRespondError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}

	mount, err := h.mounts.CreateMount(r.Context(), &req)
	if err != nil {
		mountsRespondError(w, http.StatusBadRequest, "MOUNT_ADD_ERROR", err.Error())
		return
	}

	mountsRespondJSON(w, http.StatusCreated, mount)
}

// DeleteMount godoc
// @Summary Delete a mount configuration
// @Description Removes a mount configuration by name. Unmounts first if currently mounted.
// @Tags Mounts
// @Produce json
// @Security BearerAuth
// @Param name path string true "Mount name"
// @Success 200 {object} map[string]string "status: deleted, name: mount name"
// @Failure 400 {object} ErrorResponse "INVALID_NAME - Mount name is required"
// @Failure 404 {object} ErrorResponse "MOUNT_NOT_FOUND - Mount not found"
// @Failure 500 {object} ErrorResponse "MOUNT_DELETE_ERROR"
// @Router /mounts/{name} [delete]
func (h *MountsHandler) DeleteMount(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		mountsRespondError(w, http.StatusBadRequest, "INVALID_NAME", "Mount name is required")
		return
	}

	// Look up mount by name to get ID
	mount, err := h.mounts.GetMountByName(r.Context(), name)
	if err != nil {
		mountsRespondError(w, http.StatusNotFound, "MOUNT_NOT_FOUND", err.Error())
		return
	}

	if err := h.mounts.DeleteMount(r.Context(), mount.ID); err != nil {
		mountsRespondError(w, http.StatusInternalServerError, "MOUNT_DELETE_ERROR", err.Error())
		return
	}

	mountsRespondJSON(w, http.StatusOK, map[string]string{
		"status": "deleted",
		"name":   name,
	})
}

// Mount godoc
// @Summary Mount a configured share
// @Description Mounts a previously configured SMB or NFS share to its local path
// @Tags Mounts
// @Produce json
// @Security BearerAuth
// @Param name path string true "Mount name"
// @Success 200 {object} map[string]interface{} "status: mounted, name, details"
// @Failure 400 {object} ErrorResponse "INVALID_NAME - Mount name is required"
// @Failure 404 {object} ErrorResponse "MOUNT_NOT_FOUND - Mount not found"
// @Failure 500 {object} ErrorResponse "MOUNT_ERROR - Failed to mount"
// @Router /mounts/{name}/mount [post]
func (h *MountsHandler) Mount(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		mountsRespondError(w, http.StatusBadRequest, "INVALID_NAME", "Mount name is required")
		return
	}

	// Look up mount by name to get ID
	mount, err := h.mounts.GetMountByName(r.Context(), name)
	if err != nil {
		mountsRespondError(w, http.StatusNotFound, "MOUNT_NOT_FOUND", err.Error())
		return
	}

	if err := h.mounts.MountPath(r.Context(), mount.ID); err != nil {
		mountsRespondError(w, http.StatusInternalServerError, "MOUNT_ERROR", err.Error())
		return
	}

	// Get updated mount info
	updatedMount, _ := h.mounts.GetMount(r.Context(), mount.ID)
	mountsRespondJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "mounted",
		"name":    name,
		"details": updatedMount,
	})
}

// Unmount godoc
// @Summary Unmount a share
// @Description Unmounts a currently mounted SMB or NFS share
// @Tags Mounts
// @Produce json
// @Security BearerAuth
// @Param name path string true "Mount name"
// @Success 200 {object} map[string]string "status: unmounted, name"
// @Failure 400 {object} ErrorResponse "INVALID_NAME - Mount name is required"
// @Failure 404 {object} ErrorResponse "MOUNT_NOT_FOUND - Mount not found"
// @Failure 500 {object} ErrorResponse "UNMOUNT_ERROR - Failed to unmount"
// @Router /mounts/{name}/unmount [post]
func (h *MountsHandler) Unmount(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		mountsRespondError(w, http.StatusBadRequest, "INVALID_NAME", "Mount name is required")
		return
	}

	// Look up mount by name to get ID
	mount, err := h.mounts.GetMountByName(r.Context(), name)
	if err != nil {
		mountsRespondError(w, http.StatusNotFound, "MOUNT_NOT_FOUND", err.Error())
		return
	}

	if err := h.mounts.UnmountPath(r.Context(), mount.ID); err != nil {
		mountsRespondError(w, http.StatusInternalServerError, "UNMOUNT_ERROR", err.Error())
		return
	}

	mountsRespondJSON(w, http.StatusOK, map[string]string{
		"status": "unmounted",
		"name":   name,
	})
}

// GetMountStatus godoc
// @Summary Get mount status
// @Description Returns detailed status of a specific mount including whether it is currently mounted
// @Tags Mounts
// @Produce json
// @Security BearerAuth
// @Param name path string true "Mount name"
// @Success 200 {object} map[string]interface{} "name, type, local_path, is_mounted, auto_mount"
// @Failure 400 {object} ErrorResponse "INVALID_NAME - Mount name is required"
// @Failure 404 {object} ErrorResponse "MOUNT_NOT_FOUND - Mount not found"
// @Router /mounts/{name}/status [get]
func (h *MountsHandler) GetMountStatus(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		mountsRespondError(w, http.StatusBadRequest, "INVALID_NAME", "Mount name is required")
		return
	}

	// Look up mount by name - this also checks actual mount status
	mount, err := h.mounts.GetMountByName(r.Context(), name)
	if err != nil {
		mountsRespondError(w, http.StatusNotFound, "MOUNT_NOT_FOUND", err.Error())
		return
	}

	mountsRespondJSON(w, http.StatusOK, map[string]interface{}{
		"name":       mount.Name,
		"type":       mount.Type,
		"local_path": mount.LocalPath,
		"is_mounted": mount.IsMounted,
		"auto_mount": mount.AutoMount,
	})
}

// TestConnection godoc
// @Summary Test connection to remote share
// @Description Tests connectivity to a remote SMB or NFS share without creating a mount configuration
// @Tags Mounts
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body object true "Connection test parameters" SchemaExample({"type": "smb", "remote_path": "//192.168.1.100/share", "username": "user", "password": "pass"})
// @Success 200 {object} map[string]interface{} "success: boolean, message or error"
// @Failure 400 {object} ErrorResponse "INVALID_JSON, MISSING_TYPE, or MISSING_PATH"
// @Router /mounts/test [post]
func (h *MountsHandler) TestConnection(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type       models.MountType `json:"type"`
		RemotePath string           `json:"remote_path"`
		Username   string           `json:"username,omitempty"`
		Password   string           `json:"password,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mountsRespondError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}

	if req.Type == "" {
		mountsRespondError(w, http.StatusBadRequest, "MISSING_TYPE", "Mount type is required (smb or nfs)")
		return
	}
	if req.RemotePath == "" {
		mountsRespondError(w, http.StatusBadRequest, "MISSING_PATH", "Remote path is required")
		return
	}

	err := h.mounts.TestConnection(r.Context(), string(req.Type), req.RemotePath, req.Username, req.Password)
	if err != nil {
		mountsRespondJSON(w, http.StatusOK, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	mountsRespondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Connection successful",
	})
}

// Helper functions for Mounts handlers

func mountsRespondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func mountsRespondError(w http.ResponseWriter, status int, code, message string) {
	mountsRespondJSON(w, status, map[string]string{
		"error":   code,
		"message": message,
	})
}

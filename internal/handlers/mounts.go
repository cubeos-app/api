// Package handlers provides HTTP handlers for mount management.
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"cubeos-api/internal/managers"
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

// ListMounts returns all configured mounts
// GET /api/v1/mounts
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

// GetMount returns a specific mount by name
// GET /api/v1/mounts/{name}
func (h *MountsHandler) GetMount(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		mountsRespondError(w, http.StatusBadRequest, "INVALID_NAME", "Mount name is required")
		return
	}

	mount, err := h.mounts.GetMount(r.Context(), name)
	if err != nil {
		mountsRespondError(w, http.StatusNotFound, "MOUNT_NOT_FOUND", err.Error())
		return
	}

	mountsRespondJSON(w, http.StatusOK, mount)
}

// AddMount creates a new mount configuration
// POST /api/v1/mounts
func (h *MountsHandler) AddMount(w http.ResponseWriter, r *http.Request) {
	var req managers.MountRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mountsRespondError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}

	mount, err := h.mounts.AddMount(r.Context(), &req)
	if err != nil {
		mountsRespondError(w, http.StatusBadRequest, "MOUNT_ADD_ERROR", err.Error())
		return
	}

	mountsRespondJSON(w, http.StatusCreated, mount)
}

// DeleteMount removes a mount configuration
// DELETE /api/v1/mounts/{name}
func (h *MountsHandler) DeleteMount(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		mountsRespondError(w, http.StatusBadRequest, "INVALID_NAME", "Mount name is required")
		return
	}

	if err := h.mounts.DeleteMount(r.Context(), name); err != nil {
		mountsRespondError(w, http.StatusInternalServerError, "MOUNT_DELETE_ERROR", err.Error())
		return
	}

	mountsRespondJSON(w, http.StatusOK, map[string]string{
		"status": "deleted",
		"name":   name,
	})
}

// Mount mounts a configured share
// POST /api/v1/mounts/{name}/mount
func (h *MountsHandler) Mount(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		mountsRespondError(w, http.StatusBadRequest, "INVALID_NAME", "Mount name is required")
		return
	}

	if err := h.mounts.Mount(r.Context(), name); err != nil {
		mountsRespondError(w, http.StatusInternalServerError, "MOUNT_ERROR", err.Error())
		return
	}

	// Get updated status
	status, _ := h.mounts.GetMountStatus(r.Context(), name)
	mountsRespondJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "mounted",
		"name":    name,
		"details": status,
	})
}

// Unmount unmounts a share
// POST /api/v1/mounts/{name}/unmount
func (h *MountsHandler) Unmount(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		mountsRespondError(w, http.StatusBadRequest, "INVALID_NAME", "Mount name is required")
		return
	}

	if err := h.mounts.Unmount(r.Context(), name); err != nil {
		mountsRespondError(w, http.StatusInternalServerError, "UNMOUNT_ERROR", err.Error())
		return
	}

	mountsRespondJSON(w, http.StatusOK, map[string]string{
		"status": "unmounted",
		"name":   name,
	})
}

// GetMountStatus returns detailed status of a mount
// GET /api/v1/mounts/{name}/status
func (h *MountsHandler) GetMountStatus(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		mountsRespondError(w, http.StatusBadRequest, "INVALID_NAME", "Mount name is required")
		return
	}

	status, err := h.mounts.GetMountStatus(r.Context(), name)
	if err != nil {
		mountsRespondError(w, http.StatusNotFound, "MOUNT_NOT_FOUND", err.Error())
		return
	}

	mountsRespondJSON(w, http.StatusOK, status)
}

// TestConnection tests connectivity to a remote share
// POST /api/v1/mounts/test
func (h *MountsHandler) TestConnection(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type       managers.MountType `json:"type"`
		RemotePath string             `json:"remote_path"`
		Username   string             `json:"username,omitempty"`
		Password   string             `json:"password,omitempty"`
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

	err := h.mounts.TestConnection(r.Context(), req.Type, req.RemotePath, req.Username, req.Password)
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
		"code":    code,
		"message": message,
	})
}

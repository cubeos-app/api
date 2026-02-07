package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"cubeos-api/internal/managers"
)

// SMBHandler handles SMB/Samba share management
type SMBHandler struct {
	storage *managers.StorageManager
}

// NewSMBHandler creates a new SMB handler
func NewSMBHandler(storage *managers.StorageManager) *SMBHandler {
	return &SMBHandler{storage: storage}
}

// Routes returns the SMB routes
func (h *SMBHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Get("/status", h.GetStatus)
	r.Get("/shares", h.ListShares)
	r.Post("/shares", h.CreateShare)
	r.Get("/shares/{name}", h.GetShare)
	r.Put("/shares/{name}", h.UpdateShare)
	r.Delete("/shares/{name}", h.DeleteShare)

	return r
}

// GetStatus godoc
// @Summary Get SMB service status
// @Description Returns the status of the Samba/SMB service
// @Tags SMB
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "running, version, workgroup, shares_count"
// @Failure 500 {object} ErrorResponse "Failed to get SMB status"
// @Router /smb/status [get]
func (h *SMBHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	status := h.storage.GetSMBStatus()
	writeJSON(w, http.StatusOK, status)
}

// ListShares godoc
// @Summary List SMB shares
// @Description Returns all configured SMB shares
// @Tags SMB
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "shares array"
// @Failure 500 {object} ErrorResponse "Failed to list shares"
// @Router /smb/shares [get]
func (h *SMBHandler) ListShares(w http.ResponseWriter, r *http.Request) {
	shares, err := h.storage.GetSMBShares()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list shares: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"shares": shares,
		"count":  len(shares),
	})
}

// CreateShareRequest represents a request to create an SMB share
type CreateShareRequest struct {
	Name        string   `json:"name"`
	Path        string   `json:"path"`
	Description string   `json:"description,omitempty"`
	ReadOnly    bool     `json:"read_only"`
	Browseable  bool     `json:"browseable"`
	GuestOK     bool     `json:"guest_ok"`
	ValidUsers  []string `json:"valid_users,omitempty"`
}

// CreateShare godoc
// @Summary Create SMB share
// @Description Creates a new SMB share with the specified configuration
// @Tags SMB
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body CreateShareRequest true "Share configuration"
// @Success 201 {object} managers.SMBShare "Created share"
// @Failure 400 {object} ErrorResponse "Invalid request"
// @Failure 409 {object} ErrorResponse "Share already exists"
// @Failure 500 {object} ErrorResponse "Failed to create share"
// @Router /smb/shares [post]
func (h *SMBHandler) CreateShare(w http.ResponseWriter, r *http.Request) {
	var req CreateShareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "Share name is required")
		return
	}

	if req.Path == "" {
		writeError(w, http.StatusBadRequest, "Share path is required")
		return
	}

	share := managers.SMBShare{
		Name:       req.Name,
		Path:       req.Path,
		Comment:    req.Description,
		ReadOnly:   req.ReadOnly,
		Browseable: req.Browseable,
		GuestOK:    req.GuestOK,
		ValidUsers: req.ValidUsers,
	}

	if err := h.storage.CreateSMBShare(share); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create share: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"status":  "success",
		"message": "Share created successfully",
		"share":   share.Name,
	})
}

// GetShare godoc
// @Summary Get SMB share details
// @Description Returns details for a specific SMB share
// @Tags SMB
// @Produce json
// @Security BearerAuth
// @Param name path string true "Share name"
// @Success 200 {object} managers.SMBShare "Share details"
// @Failure 404 {object} ErrorResponse "Share not found"
// @Failure 500 {object} ErrorResponse "Failed to get share"
// @Router /smb/shares/{name} [get]
func (h *SMBHandler) GetShare(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "Share name is required")
		return
	}

	shares, err := h.storage.GetSMBShares()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get shares: "+err.Error())
		return
	}

	for _, share := range shares {
		if share.Name == name {
			writeJSON(w, http.StatusOK, share)
			return
		}
	}

	writeError(w, http.StatusNotFound, "Share not found: "+name)
}

// UpdateShare godoc
// @Summary Update SMB share
// @Description Updates an existing SMB share configuration
// @Tags SMB
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param name path string true "Share name"
// @Param request body CreateShareRequest true "Updated share configuration"
// @Success 200 {object} managers.SMBShare "Updated share"
// @Failure 400 {object} ErrorResponse "Invalid request"
// @Failure 404 {object} ErrorResponse "Share not found"
// @Failure 500 {object} ErrorResponse "Failed to update share"
// @Router /smb/shares/{name} [put]
func (h *SMBHandler) UpdateShare(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "Share name is required")
		return
	}

	var req CreateShareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	share := managers.SMBShare{
		Name:       name,
		Path:       req.Path,
		Comment:    req.Description,
		ReadOnly:   req.ReadOnly,
		Browseable: req.Browseable,
		GuestOK:    req.GuestOK,
		ValidUsers: req.ValidUsers,
	}

	if err := h.storage.UpdateSMBShare(name, share); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update share: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "Share updated successfully",
	})
}

// DeleteShare godoc
// @Summary Delete SMB share
// @Description Deletes an SMB share (does not delete the underlying data)
// @Tags SMB
// @Produce json
// @Security BearerAuth
// @Param name path string true "Share name"
// @Success 200 {object} map[string]interface{} "success, message"
// @Failure 404 {object} ErrorResponse "Share not found"
// @Failure 500 {object} ErrorResponse "Failed to delete share"
// @Router /smb/shares/{name} [delete]
func (h *SMBHandler) DeleteShare(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "Share name is required")
		return
	}

	if err := h.storage.DeleteSMBShare(name); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete share: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "Share deleted successfully",
	})
}

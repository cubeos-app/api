// Package handlers provides HTTP handlers for VPN management.
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"cubeos-api/internal/managers"
)

// VPNHandler handles VPN-related HTTP requests
type VPNHandler struct {
	vpn *managers.VPNManager
}

// NewVPNHandler creates a new VPN handler
func NewVPNHandler(vpn *managers.VPNManager) *VPNHandler {
	return &VPNHandler{vpn: vpn}
}

// Routes returns the VPN router
func (h *VPNHandler) Routes() chi.Router {
	r := chi.NewRouter()

	r.Get("/status", h.GetStatus)
	r.Get("/configs", h.ListConfigs)
	r.Post("/configs", h.AddConfig)
	r.Get("/configs/{name}", h.GetConfig)
	r.Delete("/configs/{name}", h.DeleteConfig)
	r.Post("/configs/{name}/connect", h.Connect)
	r.Post("/configs/{name}/disconnect", h.Disconnect)
	r.Put("/configs/{name}/auto-connect", h.SetAutoConnect)
	r.Get("/public-ip", h.GetPublicIP)

	return r
}

// GetStatus returns the current VPN connection status
// GET /api/v1/vpn/status
func (h *VPNHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	status, err := h.vpn.GetStatus(r.Context())
	if err != nil {
		vpnRespondError(w, http.StatusInternalServerError, "VPN_STATUS_ERROR", err.Error())
		return
	}

	vpnRespondJSON(w, http.StatusOK, status)
}

// ListConfigs returns all VPN configurations
// GET /api/v1/vpn/configs
func (h *VPNHandler) ListConfigs(w http.ResponseWriter, r *http.Request) {
	configs, err := h.vpn.ListConfigs(r.Context())
	if err != nil {
		vpnRespondError(w, http.StatusInternalServerError, "VPN_LIST_ERROR", err.Error())
		return
	}

	vpnRespondJSON(w, http.StatusOK, map[string]interface{}{
		"configs": configs,
	})
}

// GetConfig returns a specific VPN configuration
// GET /api/v1/vpn/configs/{name}
func (h *VPNHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		vpnRespondError(w, http.StatusBadRequest, "INVALID_NAME", "Configuration name is required")
		return
	}

	cfg, err := h.vpn.GetConfig(r.Context(), name)
	if err != nil {
		vpnRespondError(w, http.StatusNotFound, "VPN_NOT_FOUND", err.Error())
		return
	}

	vpnRespondJSON(w, http.StatusOK, cfg)
}

// AddConfig adds a new VPN configuration
// POST /api/v1/vpn/configs
func (h *VPNHandler) AddConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string           `json:"name"`
		Type   managers.VPNType `json:"type"`
		Config string           `json:"config"` // Base64 encoded config file
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		vpnRespondError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}

	if req.Name == "" {
		vpnRespondError(w, http.StatusBadRequest, "MISSING_NAME", "Configuration name is required")
		return
	}
	if req.Type == "" {
		vpnRespondError(w, http.StatusBadRequest, "MISSING_TYPE", "VPN type is required (wireguard or openvpn)")
		return
	}
	if req.Config == "" {
		vpnRespondError(w, http.StatusBadRequest, "MISSING_CONFIG", "Configuration data is required")
		return
	}

	cfg, err := h.vpn.AddConfig(r.Context(), req.Name, req.Type, req.Config)
	if err != nil {
		vpnRespondError(w, http.StatusInternalServerError, "VPN_ADD_ERROR", err.Error())
		return
	}

	vpnRespondJSON(w, http.StatusCreated, cfg)
}

// DeleteConfig removes a VPN configuration
// DELETE /api/v1/vpn/configs/{name}
func (h *VPNHandler) DeleteConfig(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		vpnRespondError(w, http.StatusBadRequest, "INVALID_NAME", "Configuration name is required")
		return
	}

	if err := h.vpn.DeleteConfig(r.Context(), name); err != nil {
		vpnRespondError(w, http.StatusInternalServerError, "VPN_DELETE_ERROR", err.Error())
		return
	}

	vpnRespondJSON(w, http.StatusOK, map[string]string{
		"status": "deleted",
		"name":   name,
	})
}

// Connect establishes a VPN connection
// POST /api/v1/vpn/configs/{name}/connect
func (h *VPNHandler) Connect(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		vpnRespondError(w, http.StatusBadRequest, "INVALID_NAME", "Configuration name is required")
		return
	}

	if err := h.vpn.Connect(r.Context(), name); err != nil {
		vpnRespondError(w, http.StatusInternalServerError, "VPN_CONNECT_ERROR", err.Error())
		return
	}

	// Get updated status
	status, _ := h.vpn.GetStatus(r.Context())
	vpnRespondJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "connected",
		"name":    name,
		"details": status,
	})
}

// Disconnect terminates a VPN connection
// POST /api/v1/vpn/configs/{name}/disconnect
func (h *VPNHandler) Disconnect(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		vpnRespondError(w, http.StatusBadRequest, "INVALID_NAME", "Configuration name is required")
		return
	}

	if err := h.vpn.Disconnect(r.Context(), name); err != nil {
		vpnRespondError(w, http.StatusInternalServerError, "VPN_DISCONNECT_ERROR", err.Error())
		return
	}

	vpnRespondJSON(w, http.StatusOK, map[string]string{
		"status": "disconnected",
		"name":   name,
	})
}

// SetAutoConnect enables or disables auto-connect for a VPN config
// PUT /api/v1/vpn/configs/{name}/auto-connect
func (h *VPNHandler) SetAutoConnect(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		vpnRespondError(w, http.StatusBadRequest, "INVALID_NAME", "Configuration name is required")
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		vpnRespondError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}

	if err := h.vpn.SetAutoConnect(r.Context(), name, req.Enabled); err != nil {
		vpnRespondError(w, http.StatusInternalServerError, "VPN_AUTOCONNECT_ERROR", err.Error())
		return
	}

	vpnRespondJSON(w, http.StatusOK, map[string]interface{}{
		"name":         name,
		"auto_connect": req.Enabled,
	})
}

// GetPublicIP returns the current public IP address
// GET /api/v1/vpn/public-ip
func (h *VPNHandler) GetPublicIP(w http.ResponseWriter, r *http.Request) {
	ip, err := h.vpn.GetPublicIP(r.Context())
	if err != nil {
		vpnRespondError(w, http.StatusInternalServerError, "PUBLIC_IP_ERROR", err.Error())
		return
	}

	vpnRespondJSON(w, http.StatusOK, map[string]string{
		"public_ip": ip,
	})
}

// Helper functions for VPN handlers

func vpnRespondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func vpnRespondError(w http.ResponseWriter, status int, code, message string) {
	vpnRespondJSON(w, status, map[string]string{
		"code":    code,
		"message": message,
	})
}

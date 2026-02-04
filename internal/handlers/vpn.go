// Package handlers provides HTTP handlers for VPN management.
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"cubeos-api/internal/managers"
	_ "cubeos-api/internal/models" // swagger
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

// GetStatus godoc
// @Summary Get VPN connection status
// @Description Returns the current VPN connection status including active connection details
// @Tags VPN
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.VPNStatus "Current VPN status"
// @Failure 500 {object} ErrorResponse "VPN_STATUS_ERROR"
// @Router /vpn/status [get]
func (h *VPNHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	status, err := h.vpn.GetStatus(r.Context())
	if err != nil {
		vpnRespondError(w, http.StatusInternalServerError, "VPN_STATUS_ERROR", err.Error())
		return
	}

	vpnRespondJSON(w, http.StatusOK, status)
}

// ListConfigs godoc
// @Summary List all VPN configurations
// @Description Returns all saved VPN configurations (WireGuard and OpenVPN)
// @Tags VPN
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "configs: array of VPN configurations"
// @Failure 500 {object} ErrorResponse "VPN_LIST_ERROR"
// @Router /vpn/configs [get]
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

// GetConfig godoc
// @Summary Get a VPN configuration
// @Description Returns details of a specific VPN configuration by name
// @Tags VPN
// @Produce json
// @Security BearerAuth
// @Param name path string true "Configuration name"
// @Success 200 {object} models.VPNConfig "VPN configuration details"
// @Failure 400 {object} ErrorResponse "INVALID_NAME - Configuration name is required"
// @Failure 404 {object} ErrorResponse "VPN_NOT_FOUND - Configuration not found"
// @Router /vpn/configs/{name} [get]
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

// AddConfig godoc
// @Summary Add a new VPN configuration
// @Description Adds a new WireGuard or OpenVPN configuration. Config file content must be base64 encoded.
// @Tags VPN
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body object true "VPN configuration" SchemaExample({"name": "my-vpn", "type": "wireguard", "config": "W0ludGVyZmFjZV0K..."})
// @Success 201 {object} models.VPNConfig "Created VPN configuration"
// @Failure 400 {object} ErrorResponse "INVALID_JSON, MISSING_NAME, MISSING_TYPE, or MISSING_CONFIG"
// @Failure 500 {object} ErrorResponse "VPN_ADD_ERROR"
// @Router /vpn/configs [post]
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

// DeleteConfig godoc
// @Summary Delete a VPN configuration
// @Description Removes a VPN configuration by name. Disconnects first if currently active.
// @Tags VPN
// @Produce json
// @Security BearerAuth
// @Param name path string true "Configuration name"
// @Success 200 {object} map[string]string "status: deleted, name: config name"
// @Failure 400 {object} ErrorResponse "INVALID_NAME - Configuration name is required"
// @Failure 500 {object} ErrorResponse "VPN_DELETE_ERROR"
// @Router /vpn/configs/{name} [delete]
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

// Connect godoc
// @Summary Connect to VPN
// @Description Establishes a VPN connection using the specified configuration
// @Tags VPN
// @Produce json
// @Security BearerAuth
// @Param name path string true "Configuration name"
// @Success 200 {object} map[string]interface{} "status: connected, name, details"
// @Failure 400 {object} ErrorResponse "INVALID_NAME - Configuration name is required"
// @Failure 404 {object} ErrorResponse "VPN_NOT_FOUND - Configuration not found"
// @Failure 500 {object} ErrorResponse "VPN_CONNECT_ERROR"
// @Router /vpn/configs/{name}/connect [post]
func (h *VPNHandler) Connect(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		vpnRespondError(w, http.StatusBadRequest, "INVALID_NAME", "Configuration name is required")
		return
	}

	// Check if config exists first
	if _, err := h.vpn.GetConfig(r.Context(), name); err != nil {
		vpnRespondError(w, http.StatusNotFound, "VPN_NOT_FOUND", "VPN configuration not found: "+name)
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

// Disconnect godoc
// @Summary Disconnect from VPN
// @Description Terminates the active VPN connection for the specified configuration
// @Tags VPN
// @Produce json
// @Security BearerAuth
// @Param name path string true "Configuration name"
// @Success 200 {object} map[string]string "status: disconnected, name"
// @Failure 400 {object} ErrorResponse "INVALID_NAME - Configuration name is required"
// @Failure 500 {object} ErrorResponse "VPN_DISCONNECT_ERROR"
// @Router /vpn/configs/{name}/disconnect [post]
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

// SetAutoConnect godoc
// @Summary Set VPN auto-connect
// @Description Enables or disables auto-connect on boot for a VPN configuration
// @Tags VPN
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param name path string true "Configuration name"
// @Param request body object true "Auto-connect setting" SchemaExample({"enabled": true})
// @Success 200 {object} map[string]interface{} "name, auto_connect: boolean"
// @Failure 400 {object} ErrorResponse "INVALID_NAME or INVALID_JSON"
// @Failure 500 {object} ErrorResponse "VPN_AUTOCONNECT_ERROR"
// @Router /vpn/configs/{name}/auto-connect [put]
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

// GetPublicIP godoc
// @Summary Get public IP address
// @Description Returns the current public IP address (useful to verify VPN is working)
// @Tags VPN
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]string "public_ip: current public IP address"
// @Failure 500 {object} ErrorResponse "PUBLIC_IP_ERROR"
// @Router /vpn/public-ip [get]
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
		"error":   code,
		"message": message,
	})
}

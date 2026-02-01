// Package handlers provides HTTP handlers for CubeOS API.
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"cubeos-api/internal/managers"
)

// NetworkHandler handles network management endpoints.
type NetworkHandler struct {
	network *managers.NetworkManager
}

// NewNetworkHandler creates a new NetworkHandler instance.
func NewNetworkHandler(network *managers.NetworkManager) *NetworkHandler {
	return &NetworkHandler{
		network: network,
	}
}

// Routes returns the router for network endpoints.
func (h *NetworkHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Network status
	r.Get("/status", h.GetNetworkStatus)

	// Network mode
	r.Post("/mode", h.SetNetworkMode)

	// WiFi scanning and connection
	r.Get("/wifi/scan", h.ScanWiFiNetworks)
	r.Post("/wifi/connect", h.ConnectToWiFi)

	// AP configuration
	r.Route("/ap", func(r chi.Router) {
		r.Get("/clients", h.GetAPClients)
	})

	return r
}

// GetNetworkStatus returns the current network status.
// GET /api/v1/network/status
func (h *NetworkHandler) GetNetworkStatus(w http.ResponseWriter, r *http.Request) {
	status, err := h.network.GetStatus(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// SetNetworkMode changes the network operating mode.
// POST /api/v1/network/mode
func (h *NetworkHandler) SetNetworkMode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode     managers.NetworkMode `json:"mode"`
		SSID     string               `json:"ssid,omitempty"`
		Password string               `json:"password,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Mode == "" {
		writeError(w, http.StatusBadRequest, "Network mode is required")
		return
	}

	// Validate mode
	switch req.Mode {
	case managers.NetworkModeOffline, managers.NetworkModeOnlineETH, managers.NetworkModeOnlineWiFi:
		// Valid
	default:
		writeError(w, http.StatusBadRequest, "Invalid network mode. Use: offline, online_eth, online_wifi")
		return
	}

	// ONLINE_WIFI requires SSID
	if req.Mode == managers.NetworkModeOnlineWiFi && req.SSID == "" {
		writeError(w, http.StatusBadRequest, "SSID is required for online_wifi mode")
		return
	}

	if err := h.network.SetMode(r.Context(), req.Mode, req.SSID, req.Password); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Return updated status
	status, _ := h.network.GetStatus(r.Context())
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Network mode changed to " + string(req.Mode),
		"status":  status,
	})
}

// ScanWiFiNetworks scans for available WiFi networks.
// GET /api/v1/network/wifi/scan
func (h *NetworkHandler) ScanWiFiNetworks(w http.ResponseWriter, r *http.Request) {
	// Get optional interface parameter, empty string uses default
	iface := r.URL.Query().Get("interface")

	networks, err := h.network.ScanWiFiNetworks(r.Context(), iface)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"networks": networks,
		"count":    len(networks),
	})
}

// ConnectToWiFi connects to a WiFi network.
// POST /api/v1/network/wifi/connect
func (h *NetworkHandler) ConnectToWiFi(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Interface string `json:"interface,omitempty"`
		SSID      string `json:"ssid"`
		Password  string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.SSID == "" {
		writeError(w, http.StatusBadRequest, "SSID is required")
		return
	}

	// Interface is optional - manager uses default if empty
	if err := h.network.ConnectToWiFi(r.Context(), req.Interface, req.SSID, req.Password); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to connect: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Connected to " + req.SSID,
	})
}

// GetAPClients returns connected AP clients.
// GET /api/v1/network/ap/clients
func (h *NetworkHandler) GetAPClients(w http.ResponseWriter, r *http.Request) {
	clients, err := h.network.GetConnectedClients()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"clients": clients,
		"count":   len(clients),
	})
}

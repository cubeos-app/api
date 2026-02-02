// Package handlers provides HTTP handlers for the CubeOS API.
package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"cubeos-api/internal/hal"
	"cubeos-api/internal/managers"
)

// NetworkHandler handles network management endpoints.
type NetworkHandler struct {
	network   *managers.NetworkManager
	halClient *hal.Client
}

// NewNetworkHandler creates a new NetworkHandler instance.
func NewNetworkHandler(network *managers.NetworkManager, halClient *hal.Client) *NetworkHandler {
	return &NetworkHandler{
		network:   network,
		halClient: halClient,
	}
}

// Routes returns the router for network endpoints.
func (h *NetworkHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Network status and mode
	r.Get("/status", h.GetNetworkStatus)
	r.Post("/mode", h.SetNetworkMode)

	// Internet connectivity
	r.Get("/internet", h.GetInternetStatus)

	// Network interfaces
	r.Get("/interfaces", h.GetInterfaces)
	r.Get("/interfaces/detailed", h.GetInterfacesDetailed)

	// WiFi scanning and connection
	r.Get("/wifi/scan", h.ScanWiFiNetworks)
	r.Post("/wifi/connect", h.ConnectToWiFi)

	// Access Point management
	r.Route("/wifi/ap", func(r chi.Router) {
		r.Get("/status", h.GetAPStatus)
		r.Post("/restart", h.RestartAP)
		r.Get("/clients", h.GetAPClients)
		r.Post("/clients/{mac}/kick", h.KickAPClient)
		r.Post("/clients/{mac}/block", h.BlockAPClient)
	})

	// Legacy AP configuration routes (keep for backward compatibility)
	r.Route("/ap", func(r chi.Router) {
		r.Get("/config", h.GetAPConfig)
		r.Put("/config", h.UpdateAPConfig)
		r.Get("/clients", h.GetAPClients)
	})

	// Traffic statistics
	r.Get("/traffic", h.GetTrafficStats)
	r.Get("/traffic/{iface}/history", h.GetTrafficHistory)

	return r
}

// =============================================================================
// Network Status and Mode
// =============================================================================

// GetNetworkStatus returns the current network status.
// GET /api/v1/network/status
func (h *NetworkHandler) GetNetworkStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	status, err := h.network.GetStatus(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// SetNetworkMode changes the network operating mode.
// POST /api/v1/network/mode
func (h *NetworkHandler) SetNetworkMode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		Mode     string `json:"mode"`
		SSID     string `json:"ssid,omitempty"`
		Password string `json:"password,omitempty"`
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
	validModes := map[string]bool{
		"offline":     true,
		"online_eth":  true,
		"online_wifi": true,
		"server_eth":  true,
		"server_wifi": true,
	}

	if !validModes[req.Mode] {
		writeError(w, http.StatusBadRequest, "Invalid network mode. Valid modes: offline, online_eth, online_wifi, server_eth, server_wifi")
		return
	}

	// WiFi modes require SSID
	if (req.Mode == "online_wifi" || req.Mode == "server_wifi") && req.SSID == "" {
		writeError(w, http.StatusBadRequest, "SSID is required for WiFi modes")
		return
	}

	// Convert string to managers.NetworkMode
	var mode managers.NetworkMode
	switch req.Mode {
	case "offline":
		mode = managers.NetworkModeOffline
	case "online_eth":
		mode = managers.NetworkModeOnlineETH
	case "online_wifi":
		mode = managers.NetworkModeOnlineWiFi
	case "server_eth":
		mode = managers.NetworkModeServerETH
	case "server_wifi":
		mode = managers.NetworkModeServerWiFi
	}

	if err := h.network.SetMode(ctx, mode, req.SSID, req.Password); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Return updated status
	status, _ := h.network.GetStatus(ctx)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Network mode changed to " + req.Mode,
		"status":  status,
	})
}

// =============================================================================
// Internet Connectivity
// =============================================================================

// GetInternetStatus checks internet connectivity.
// GET /api/v1/network/internet
func (h *NetworkHandler) GetInternetStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Try to check connectivity via HAL
	if h.halClient != nil {
		status, err := h.halClient.GetNetworkStatus(ctx)
		if err == nil {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"connected":    status["internet"],
				"check_target": "1.1.1.1",
				"method":       "hal",
			})
			return
		}
	}

	// Fallback: use network manager
	netStatus, err := h.network.GetStatus(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"connected":    netStatus.Internet,
		"check_target": "1.1.1.1",
		"method":       "manager",
	})
}

// =============================================================================
// Network Interfaces
// =============================================================================

// GetInterfaces returns a list of network interfaces.
// GET /api/v1/network/interfaces
func (h *NetworkHandler) GetInterfaces(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	interfaces, err := h.halClient.ListInterfaces(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list interfaces: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"interfaces": interfaces,
	})
}

// GetInterfacesDetailed returns detailed information about all network interfaces.
// GET /api/v1/network/interfaces/detailed
func (h *NetworkHandler) GetInterfacesDetailed(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	interfaces, err := h.halClient.ListInterfaces(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list interfaces: "+err.Error())
		return
	}

	// Enrich interface data
	type DetailedInterface struct {
		Name          string   `json:"name"`
		IsUp          bool     `json:"is_up"`
		MACAddress    string   `json:"mac_address"`
		IPv4Addresses []string `json:"ipv4_addresses"`
		IPv6Addresses []string `json:"ipv6_addresses"`
		MTU           int      `json:"mtu"`
		Type          string   `json:"type"` // ethernet, wifi, loopback, bridge, virtual
		Role          string   `json:"role"` // ap, client, wan, unused
		IsWireless    bool     `json:"is_wireless"`
	}

	var detailed []DetailedInterface
	for _, iface := range interfaces {
		di := DetailedInterface{
			Name:          iface.Name,
			IsUp:          iface.IsUp,
			MACAddress:    iface.MACAddress,
			IPv4Addresses: iface.IPv4Addresses,
			IPv6Addresses: iface.IPv6Addresses,
			MTU:           iface.MTU,
		}

		// Determine interface type and role
		switch {
		case iface.Name == "lo":
			di.Type = "loopback"
			di.Role = "system"
		case strings.HasPrefix(iface.Name, "eth"):
			di.Type = "ethernet"
			di.Role = "wan"
		case iface.Name == "wlan0":
			di.Type = "wifi"
			di.Role = "ap"
			di.IsWireless = true
		case strings.HasPrefix(iface.Name, "wlan") || strings.HasPrefix(iface.Name, "wlx"):
			di.Type = "wifi"
			di.Role = "client"
			di.IsWireless = true
		case strings.HasPrefix(iface.Name, "docker") || strings.HasPrefix(iface.Name, "br-"):
			di.Type = "bridge"
			di.Role = "container"
		case strings.HasPrefix(iface.Name, "veth"):
			di.Type = "virtual"
			di.Role = "container"
		default:
			di.Type = "unknown"
			di.Role = "unused"
		}

		detailed = append(detailed, di)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"interfaces": detailed,
		"count":      len(detailed),
	})
}

// =============================================================================
// WiFi Scanning and Connection
// =============================================================================

// ScanWiFiNetworks scans for available WiFi networks.
// GET /api/v1/network/wifi/scan
func (h *NetworkHandler) ScanWiFiNetworks(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Optional interface parameter
	_ = r.URL.Query().Get("interface") // interface filter not yet implemented

	networks, err := h.network.ScanWiFiNetworks(ctx)
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
	ctx := r.Context()

	var req struct {
		SSID      string `json:"ssid"`
		Password  string `json:"password"`
		Interface string `json:"interface,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.SSID == "" {
		writeError(w, http.StatusBadRequest, "SSID is required")
		return
	}

	if err := h.network.ConnectToWiFi(ctx, req.SSID, req.Password); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Connected to WiFi network: " + req.SSID,
	})
}

// =============================================================================
// Access Point Management
// =============================================================================

// GetAPStatus returns detailed AP status.
// GET /api/v1/network/wifi/ap/status
func (h *NetworkHandler) GetAPStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get AP config
	config, err := h.network.GetAPConfig(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get AP config: "+err.Error())
		return
	}

	// Get connected clients
	clients, err := h.network.GetConnectedClients()
	if err != nil {
		// Don't fail completely if we can't get clients
		clients = nil
	}

	// Check if hostapd is running via HAL
	var hostapdRunning bool
	if h.halClient != nil {
		status, err := h.halClient.GetServiceStatus(ctx, "hostapd")
		if err == nil && status != nil {
			hostapdRunning = status.Active
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":   config != nil,
		"running":   hostapdRunning,
		"ssid":      config.SSID,
		"channel":   config.Channel,
		"interface": "wlan0", // default AP interface
		"hidden":    config.Hidden,
		"clients":   len(clients),
	})
}

// RestartAP restarts the access point.
// POST /api/v1/network/wifi/ap/restart
func (h *NetworkHandler) RestartAP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.RestartService(ctx, "hostapd"); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to restart AP: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Access point restarted",
	})
}

// GetAPClients returns connected AP clients.
// GET /api/v1/network/wifi/ap/clients
// GET /api/v1/network/ap/clients (legacy)
func (h *NetworkHandler) GetAPClients(w http.ResponseWriter, r *http.Request) {
	_ = r.Context() // ctx available if needed

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

// KickAPClient disconnects a client from the AP.
// POST /api/v1/network/wifi/ap/clients/{mac}/kick
func (h *NetworkHandler) KickAPClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	mac := chi.URLParam(r, "mac")
	if mac == "" {
		writeError(w, http.StatusBadRequest, "MAC address is required")
		return
	}

	// Validate MAC format
	if !isValidMAC(mac) {
		writeError(w, http.StatusBadRequest, "Invalid MAC address format")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.KickAPClient(ctx, mac); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to kick client: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Client " + mac + " disconnected",
	})
}

// BlockAPClient blocks a client from connecting to the AP.
// POST /api/v1/network/wifi/ap/clients/{mac}/block
func (h *NetworkHandler) BlockAPClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	mac := chi.URLParam(r, "mac")
	if mac == "" {
		writeError(w, http.StatusBadRequest, "MAC address is required")
		return
	}

	// Validate MAC format
	if !isValidMAC(mac) {
		writeError(w, http.StatusBadRequest, "Invalid MAC address format")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	if err := h.halClient.BlockAPClient(ctx, mac); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to block client: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Client " + mac + " blocked",
	})
}

// =============================================================================
// Legacy AP Configuration (backward compatibility)
// =============================================================================

// GetAPConfig returns the AP configuration.
// GET /api/v1/network/ap/config
func (h *NetworkHandler) GetAPConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	config, err := h.network.GetAPConfig(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, config)
}

// UpdateAPConfig updates the AP configuration.
// PUT /api/v1/network/ap/config
func (h *NetworkHandler) UpdateAPConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		SSID     string `json:"ssid"`
		Password string `json:"password"`
		Channel  int    `json:"channel"`
		Hidden   bool   `json:"hidden"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.SSID == "" {
		writeError(w, http.StatusBadRequest, "SSID is required")
		return
	}

	if len(req.Password) > 0 && len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "Password must be at least 8 characters")
		return
	}

	if err := h.network.UpdateAPConfig(ctx, req.SSID, req.Password, req.Channel, req.Hidden); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "AP configuration updated",
	})
}

// =============================================================================
// Traffic Statistics
// =============================================================================

// GetTrafficStats returns current traffic statistics for all interfaces.
// GET /api/v1/network/traffic
func (h *NetworkHandler) GetTrafficStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	stats, err := h.halClient.GetTrafficStats(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get traffic stats: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"stats": stats,
	})
}

// GetTrafficHistory returns traffic history for a specific interface.
// GET /api/v1/network/traffic/{iface}/history
func (h *NetworkHandler) GetTrafficHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	iface := chi.URLParam(r, "iface")
	if iface == "" {
		writeError(w, http.StatusBadRequest, "Interface name is required")
		return
	}

	if h.halClient == nil {
		writeError(w, http.StatusServiceUnavailable, "HAL service unavailable")
		return
	}

	// Get duration from query params (default: 1h)
	duration := r.URL.Query().Get("duration")
	if duration == "" {
		duration = "1h"
	}

	history, err := h.halClient.GetTrafficHistory(ctx, iface, duration)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get traffic history: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"interface": iface,
		"duration":  duration,
		"history":   history,
	})
}

// =============================================================================
// Helper Functions
// =============================================================================

// isValidMAC validates a MAC address format
func isValidMAC(mac string) bool {
	// Accept formats: AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF
	mac = strings.ToUpper(mac)
	mac = strings.ReplaceAll(mac, "-", ":")

	parts := strings.Split(mac, ":")
	if len(parts) != 6 {
		return false
	}

	for _, part := range parts {
		if len(part) != 2 {
			return false
		}
		for _, c := range part {
			if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}
